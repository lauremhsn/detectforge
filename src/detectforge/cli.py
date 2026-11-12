"""Command line: `detectforge {validate,convert,harness,compare,sigmahq,dataset} ...`.

Prints JSON to stdout.
"""

import argparse
import json
import sys
from pathlib import Path

from detectforge.config import get_settings
from detectforge.dataset import argfuscator, atomic, mutate, selection
from detectforge.events import load_events
from detectforge.harness import run
from detectforge.harness.compare import compare
from detectforge.reference import sigmahq
from detectforge.reference.index import MAX_LIMIT, ReferenceIndex
from detectforge.rules.convert import TARGETS, convert_rule
from detectforge.rules.parse import RuleError
from detectforge.rules.validate import validate_rule


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

    dataset_sub = sub.add_parser("dataset", help="evaluation dataset").add_subparsers(
        dest="dataset_command", required=True
    )
    p = dataset_sub.add_parser("select", help="build the rule set and base attacks from a selection config")
    p.add_argument("--config", type=Path, default=Path("data/eval/selection_config.yml"))
    p.set_defaults(handler=_dataset_select)

    p = dataset_sub.add_parser("mutate", help="generate command-line mutations of the base attacks")
    p.set_defaults(handler=_dataset_mutate)

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
