"""Command line: `detectforge {validate,convert,harness} ...`. Prints JSON to stdout."""

import argparse
import json
import sys
from pathlib import Path

from detectforge.events import load_events
from detectforge.harness import run
from detectforge.rules.convert import TARGETS, convert_rule
from detectforge.rules.parse import RuleError
from detectforge.rules.validate import validate_rule


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detectforge")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate a Sigma rule")
    p.add_argument("rule", type=Path)

    p = sub.add_parser("convert", help="convert a Sigma rule to a SIEM query")
    p.add_argument("rule", type=Path)
    p.add_argument("--target", choices=sorted(TARGETS), default="lucene")

    p = sub.add_parser("harness", help="score a Sigma rule against an events JSONL file")
    p.add_argument("rule", type=Path)
    p.add_argument("events", type=Path)

    args = parser.parse_args(argv)
    rule_yaml = args.rule.read_text(encoding="utf-8")

    if args.command == "validate":
        result = validate_rule(rule_yaml)
        print(result.model_dump_json(indent=2))
        return 0 if result.valid else 1
    if args.command == "convert":
        try:
            print(json.dumps(convert_rule(rule_yaml, args.target), indent=2))
        except RuleError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        return 0
    scorecard = run(rule_yaml, load_events(args.events))
    print(scorecard.model_dump_json(indent=2))
    return 0 if scorecard.valid else 1
