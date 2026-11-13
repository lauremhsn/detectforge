"""Command line: `detectforge {validate,convert,harness,compare,sigmahq,harden,llm} ...`."""

import argparse
import json
import sys
from pathlib import Path

from detectforge.agent.runner import run_hardening
from detectforge.config import get_settings
from detectforge.events import load_events
from detectforge.harness import run
from detectforge.harness.compare import compare
from detectforge.llm import LLMError, OpenAICompatibleClient, list_free_tool_models
from detectforge.reference import sigmahq
from detectforge.reference.index import MAX_LIMIT, ReferenceIndex
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

    p = sub.add_parser("harden", help="run the agent to harden an existing rule (tuning split only)")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--rule", type=Path, help="Sigma rule file")
    source.add_argument("--rule-id", help="SigmaHQ rule id from the reference index")
    p.add_argument("--technique", required=True, help="ATT&CK technique whose events to use")
    p.add_argument("--events", type=Path, action="append", required=True, help="events JSONL (repeatable)")
    p.add_argument("--out", type=Path, default=Path("data/runs"), help="where to save the run and rule")
    p.set_defaults(handler=_harden)

    llm_sub = sub.add_parser("llm", help="LLM provider helpers").add_subparsers(
        dest="llm_command", required=True
    )
    p = llm_sub.add_parser("models", help="list free models that support tool calling (OpenRouter)")
    p.set_defaults(handler=_llm_models)

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
            rule_yaml, args.technique, events, client, settings.model, index, args.out, make_tracer(settings)
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
