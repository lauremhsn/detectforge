"""Command line for detectforge: validate, convert, harness, compare, sigmahq, harden,
harden-selection, llm, dataset. Prints JSON to stdout.
"""

import argparse
import json
import sys
from pathlib import Path

from detectforge.agent.batch import harden_selection, load_selection
from detectforge.agent.runner import run_hardening
from detectforge.config import get_settings
from detectforge.dataset import argfuscator, atomic, hard_negatives, mutate, selection
from detectforge.eval import arms
from detectforge.events import load_events
from detectforge.harness import run
from detectforge.harness.compare import compare
from detectforge.intake import interpret_request
from detectforge.llm import LLMError, OpenAICompatibleClient, key_info, list_free_tool_models
from detectforge.reference import sigmahq
from detectforge.reference.index import MAX_LIMIT, ReferenceIndex
from detectforge.review import calls_today
from detectforge.rules.convert import TARGETS, convert_rule
from detectforge.rules.parse import RuleError
from detectforge.rules.validate import validate_rule
from detectforge.tracing import make_tracer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detectforge")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate a Sigma rule")
    p.add_argument("rule", type=Path)
    p.set_defaults(handler=_validate)

    p = sub.add_parser("convert", help="convert a Sigma rule to a SIEM query")
    p.add_argument("rule", type=Path)
    p.add_argument("--target", choices=sorted(TARGETS), default="lucene")
    p.set_defaults(handler=_convert)

    p = sub.add_parser("harness", help="score a Sigma rule against an events JSONL file")
    p.add_argument("rule", type=Path)
    p.add_argument("events", type=Path)
    p.set_defaults(handler=_harness)

    p = sub.add_parser("compare", help="before/after report for two versions of a rule on the same events")
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("events", type=Path)
    p.add_argument("--split", choices=["tune", "heldout"], help="only score events from this split")
    p.add_argument("--technique", help="only score events for this technique")
    p.set_defaults(handler=_compare)

    sigma_sub = sub.add_parser("sigmahq", help="SigmaHQ reference rules").add_subparsers(
        dest="sigmahq_command", required=True
    )
    p = sigma_sub.add_parser("fetch", help=f"download SigmaHQ {sigmahq.RELEASE_TAG} and build the index")
    p.add_argument("--zip", type=Path, help="use an already downloaded release zip (checksum still verified)")
    p.set_defaults(handler=_sigmahq_fetch)

    p = sigma_sub.add_parser("search", help="search the reference index")
    p.add_argument("--technique")
    p.add_argument("--query")
    p.add_argument("--exclude-technique")
    p.add_argument("--limit", type=int, default=5, choices=range(1, MAX_LIMIT + 1), metavar=f"1-{MAX_LIMIT}")
    p.add_argument("--show-yaml", action="store_true")
    p.set_defaults(handler=_sigmahq_search)

    p = sub.add_parser("intake", help="map a plain-language request to ATT&CK techniques")
    p.add_argument("request", help='e.g. "detect scheduled-task persistence"')
    p.add_argument("--no-model", action="store_true", help="keyword search only (no model call)")
    p.set_defaults(handler=_intake)

    p = sub.add_parser("harden-selection", help="harden every rule of an evaluation selection (e.g. dev)")
    p.add_argument("--selection", type=Path, default=Path("data/eval/selection.yml"))
    p.add_argument(
        "--events", type=Path, action="append", help="events JSONL (repeatable; default: data/eval)"
    )
    p.add_argument("--split", default="dev", choices=["dev", "test"])
    p.add_argument("--all", action="store_true", help="also run rules that already detect every mutation")
    p.add_argument("--limit", type=int, help="at most this many agent runs (saves the free model quota)")
    p.add_argument("--rule-id", action="append", help="only this SigmaHQ rule id (repeatable)")
    p.add_argument(
        "--repeat", type=int, default=1, help="runs wanted per rule; saved runs with the same setup count"
    )
    p.add_argument(
        "--max-calls",
        type=int,
        help="model-call cap for the whole batch (a run starts only if its budget fits)",
    )
    p.add_argument("--dry-run", action="store_true", help="show what would run, without calling the model")
    p.set_defaults(handler=_harden_selection)

    dataset_sub = sub.add_parser("dataset", help="evaluation dataset").add_subparsers(
        dest="dataset_command", required=True
    )
    p = dataset_sub.add_parser("select", help="build the rule set and base attacks from a selection config")
    p.add_argument("--config", type=Path, default=Path("data/eval/selection_config.yml"))
    p.set_defaults(handler=_dataset_select)
    p = sub.add_parser("harden", help="run the agent to harden an existing rule (tuning split only)")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--rule", type=Path, help="Sigma rule file")
    source.add_argument("--rule-id", help="SigmaHQ rule id from the reference index")
    p.add_argument("--technique", required=True, help="ATT&CK technique whose events to use")
    p.add_argument("--events", type=Path, action="append", required=True, help="events JSONL (repeatable)")
    p.add_argument("--out", type=Path, help="where to save the run and rule (default: data/runs)")
    p.set_defaults(handler=_harden)

    llm_sub = sub.add_parser("llm", help="LLM provider helpers").add_subparsers(
        dest="llm_command", required=True
    )
    p = llm_sub.add_parser("models", help="list free models that support tool calling (OpenRouter)")
    p.set_defaults(handler=_llm_models)
    p = llm_sub.add_parser("quota", help="model calls used today and the key tier (no model call)")
    p.set_defaults(handler=_llm_quota)

    p = dataset_sub.add_parser("mutate", help="generate command-line mutations of the base attacks")
    p.set_defaults(handler=_dataset_mutate)

    p = dataset_sub.add_parser("negatives", help="build benign hard-negative events from the config")
    p.set_defaults(handler=_dataset_negatives)

    eval_sub = sub.add_parser("eval", help="run an evaluation arm").add_subparsers(
        dest="eval_command", required=True
    )
    p = eval_sub.add_parser("community", help="Arm 1: score the community rules as-is against all mutations")
    p.set_defaults(handler=_eval_community)

    args = parser.parse_args(argv)
    return args.handler(args)


def _validate(args: argparse.Namespace) -> int:
    result = validate_rule(args.rule.read_text(encoding="utf-8"))
    print(result.model_dump_json(indent=2))
    return 0 if result.valid else 1


def _convert(args: argparse.Namespace) -> int:
    try:
        print(json.dumps(convert_rule(args.rule.read_text(encoding="utf-8"), args.target), indent=2))
    except RuleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def _harness(args: argparse.Namespace) -> int:
    scorecard = run(args.rule.read_text(encoding="utf-8"), load_events(args.events))
    print(scorecard.model_dump_json(indent=2))
    return 0 if scorecard.valid else 1


def _compare(args: argparse.Namespace) -> int:
    events = [
        e
        for e in load_events(args.events)
        if (args.split is None or e.split == args.split)
        and (args.technique is None or e.technique == args.technique)
    ]
    report = compare(args.before.read_text(encoding="utf-8"), args.after.read_text(encoding="utf-8"), events)
    print(report.model_dump_json(indent=2))
    return 0 if report.valid else 1


def _harden(args: argparse.Namespace) -> int:
    settings = get_settings()
    index = _load_index_or_none()
    if args.rule_id:
        rule = next((r for r in index.rules if r.id == args.rule_id), None) if index else None
        if rule is None:
            print(f"error: rule {args.rule_id} not in the SigmaHQ index", file=sys.stderr)
            return 1
        rule_yaml = rule.rule_yaml
    else:
        rule_yaml = args.rule.read_text(encoding="utf-8")
    events = [e for path in args.events for e in load_events(path)]
    try:
        client = OpenAICompatibleClient.from_settings(settings)
        outcome = run_hardening(
            rule_yaml,
            args.technique,
            events,
            client,
            settings.model,
            index,
            args.out or settings.runs_dir,
            make_tracer(settings),
        )
    except (LLMError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    run, evaluation = outcome.run, outcome.heldout_evaluation
    print(f"status:       {run.status} ({run.final_source})")
    for reason in run.reasons:
        print(f"  - {reason}")
    print(
        f"tuning:       evasion resistance {_pct(run.tuning_evasion_resistance_before)} -> "
        f"{_pct(run.tuning_evasion_resistance_after)}, false alarms "
        f"{run.tuning_false_alarms_before} -> {run.tuning_false_alarms_after}"
    )
    if evaluation is not None:
        print(
            f"held-out:     evasion resistance {_pct(evaluation.evasion_resistance_before)} -> "
            f"{_pct(evaluation.evasion_resistance_after)} (evaluation only; never shown to the agent)"
        )
    print(
        f"cost:         {len(run.model_calls)} model calls, "
        f"{run.prompt_tokens + run.completion_tokens} tokens, "
        f"{run.tuning_runs_used} tuning runs, {run.duration_s}s"
    )
    print(f"saved:        {outcome.saved_to}")
    print(
        f"trace:        {outcome.trace_url or 'tracing off (set LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY)'}"
    )
    return 0


def _harden_selection(args: argparse.Namespace) -> int:
    settings = get_settings()
    index = _load_index_or_none()
    if index is None:
        print("error: no SigmaHQ index; run `detectforge sigmahq fetch`", file=sys.stderr)
        return 1
    # Default: attacks, their mutations, and the class-A benign look-alikes (class B, which can't be
    # told apart from attacks by command line, is reported separately and never counted as a mistake).
    paths = args.events or [
        Path("data/eval/base_events.jsonl"),
        Path("data/eval/mutations.jsonl"),
        Path("data/eval/benign_events.jsonl"),
    ]
    try:
        events = [e for path in paths for e in load_events(path)]
        selection = load_selection(args.selection)
        client = None if args.dry_run else OpenAICompatibleClient.from_settings(settings)
    except (OSError, LLMError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    items = harden_selection(
        selection,
        events,
        index,
        client,
        settings.model,
        settings.runs_dir,
        make_tracer(settings),
        split=args.split,
        only_improvable=not args.all,
        limit=args.limit,
        repeat=args.repeat,
        max_calls=args.max_calls,
        rule_ids=set(args.rule_id) if args.rule_id else None,
        dry_run=args.dry_run,
        settings=settings,
    )
    print(f"{'technique':10} {'tuning':>15} {'held-out':>15} {'calls':>5}  result  rule")
    for i in items:
        ran = i.action in ("hardened", "reused")
        tuning = f"{_pct(i.tuning_before)} -> {_pct(i.tuning_after)}" if ran else _pct(i.tuning_before)
        heldout = f"{_pct(i.heldout_before)} -> {_pct(i.heldout_after)}" if ran else ""
        result = f"{i.status} (reused)" if i.action == "reused" else i.status if ran else i.action
        print(f"{i.technique:10} {tuning:>15} {heldout:>15} {i.model_calls:>5}  {result}  {i.title[:50]}")
        if i.note:
            print(f"{'':10} {i.note}")
    if args.dry_run:
        planned = sum(i.action == "planned" for i in items)
        print(
            f"\ndry run: {planned} runs would start, at most {planned * settings.max_model_calls} model "
            f"calls ({settings.max_model_calls} per run); nothing was sent to the model"
        )
        return 0
    calls = sum(i.model_calls for i in items)
    print(f"\n{calls} model calls; runs saved to {settings.runs_dir} (see the Review tab)")
    return 0


def _intake(args: argparse.Namespace) -> int:
    index = _load_index_or_none()
    if index is None:
        print("error: no SigmaHQ index; run `detectforge sigmahq fetch`", file=sys.stderr)
        return 1
    client = None
    if not args.no_model:
        try:
            client = OpenAICompatibleClient.from_settings(get_settings())
        except LLMError:
            client = None  # no key: intake degrades to keyword search
    print(interpret_request(args.request, index, client).model_dump_json(indent=2))
    return 0


def _llm_quota(args: argparse.Namespace) -> int:
    settings = get_settings()
    print(f"model calls saved in agent runs today (UTC): {calls_today(settings.runs_dir)}")
    print("(not counted: intake requests, the deployed app, and other machines sharing the key)")
    if settings.llm_api_key is None:
        print("no API key set, so the provider can't be asked about the key")
        return 0
    try:
        info = key_info(settings.llm_base_url, settings.llm_api_key.get_secret_value())
    except LLMError as e:
        print(f"provider: {e}")
        return 0
    free = info.get("is_free_tier")
    print(f"provider: free tier = {free}, credit limit = {info.get('limit')}, usage = {info.get('usage')}")
    if free:
        print("OpenRouter free tier: about 50 free-model requests a day (1000 with $10 of credits bought)")
    return 0


def _llm_models(args: argparse.Namespace) -> int:
    for model in list_free_tool_models(get_settings().llm_base_url):
        print(f"{model['id']}  (context {model['context_length']})")
    return 0


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _load_index_or_none() -> ReferenceIndex | None:
    try:
        return ReferenceIndex.load(_sigmahq_dir())
    except FileNotFoundError:
        return None


def _sigmahq_dir() -> Path:
    return get_settings().data_dir / "sigmahq"


def _sigmahq_fetch(args: argparse.Namespace) -> int:
    try:
        meta = sigmahq.fetch_and_build(_sigmahq_dir(), args.zip)
    except sigmahq.ReleaseIntegrityError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(meta, indent=2))
    return 0


def _sigmahq_search(args: argparse.Namespace) -> int:
    index = ReferenceIndex.load(_sigmahq_dir())
    try:
        hits = index.search(args.technique, args.query, args.limit, args.exclude_technique)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    exclude = None if args.show_yaml else {"rule": {"rule_yaml", "detection_text"}}
    print(json.dumps([h.model_dump(exclude=exclude) for h in hits], indent=2))
    return 0


def _dataset_select(args: argparse.Namespace) -> int:
    data_dir = get_settings().data_dir
    try:
        result = selection.build_selection(
            selection.load_config(args.config),
            ReferenceIndex.load(_sigmahq_dir()),
            data_dir / "atomic-red-team",
        )
    except (selection.SelectionError, atomic.AtomicFetchError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    selection.write_selection(
        result, data_dir / "eval" / "selection.yml", data_dir / "eval" / "base_events.jsonl"
    )
    splits = [r.split for r in result.rules]
    print(
        json.dumps(
            {
                "rules": len(result.rules),
                "dev_rules": splits.count("dev"),
                "test_rules": splits.count("test"),
                "techniques": len({r.technique for r in result.rules}),
                "base_attacks": len(result.base_attacks),
            },
            indent=2,
        )
    )
    return 0


def _dataset_mutate(args: argparse.Namespace) -> int:
    import collections

    data_dir = get_settings().data_dir
    base = load_events(data_dir / "eval" / "base_events.jsonl")
    try:
        mutations = mutate.build_mutations(base, data_dir / "argfuscator")
    except argfuscator.ArgfuscatorFetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    out_path = data_dir / "eval" / "mutations.jsonl"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for event in mutations:
            f.write(event.model_dump_json(exclude_none=True) + "\n")
    per_transform = collections.Counter(m.transform for m in mutations)
    per_split = collections.Counter(m.split for m in mutations)
    print(
        json.dumps(
            {
                "base_attacks": len(base),
                "mutations": len(mutations),
                "per_transform": dict(per_transform),
                "per_split": dict(per_split),
            },
            indent=2,
        )
    )
    return 0


def _dataset_negatives(args: argparse.Namespace) -> int:
    data_dir = get_settings().data_dir
    config = hard_negatives.load(data_dir / "eval" / "hard_negatives.yml")
    class_a, class_b = hard_negatives.build_events(config)
    for events, name in ((class_a, "benign_events.jsonl"), (class_b, "benign_ambiguous.jsonl")):
        with open(data_dir / "eval" / name, "w", encoding="utf-8", newline="\n") as f:
            for event in events:
                f.write(event.model_dump_json(exclude_none=True) + "\n")
    print(json.dumps({"class_a": len(class_a), "class_b": len(class_b)}, indent=2))
    return 0


def _eval_community(args: argparse.Namespace) -> int:
    import yaml

    data_dir = get_settings().data_dir
    selection = yaml.safe_load((data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))
    index = ReferenceIndex.load(_sigmahq_dir())
    events = load_events(data_dir / "eval" / "base_events.jsonl") + load_events(
        data_dir / "eval" / "mutations.jsonl"
    )
    result = arms.run_community_arm(selection, index, events)
    out_dir = data_dir / "eval" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "arm1_community.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "arm": result.arm,
                "rules": result.rule_count,
                "overall_evasion_resistance": result.overall_evasion_resistance,
                "by_transform": result.resistance_by_transform,
                "by_mutation_split": result.resistance_by_mutation_split,
                "by_selection_split": result.resistance_by_selection_split,
                "fully_robust_rules": result.rules_fully_robust,
                "evaded_rules": result.rules_evaded,
            },
            indent=2,
        )
    )
    print(f"wrote {out_dir / 'arm1_community.json'}", file=sys.stderr)
    return 0
