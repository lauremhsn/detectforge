"""Lint a proposed rule for problems the harness's scores can't see.

Hardening may broaden a rule, never quietly narrow it:
- fields: every field the original used must still be used. Branches on fields our events lack
  (e.g. Hashes, Description) are untestable here; dropping them would lose real-world coverage
  without any score noticing.
- filters: every exclusion (a value under a NOT in the condition) must still be excluded. Dropping
  a filter for a known false positive would bring that false alarm back in production, and our
  hard negatives may not contain it.

Overfitting (memorising the test attacks instead of describing the behavior):
- unusual characters: invisible or look-alike Unicode characters (literal, or written as \\u / \\x
  escapes) that the original didn't contain. Real Sigma rules essentially never need them; if the
  agent adds them, it copied the exact tricks our mutations used, and new variants would get through.
- copied literals: long strings taken verbatim from the tuning attacks (e.g. a test task name).
  Sometimes legitimate (a registry path), so these are reported for the human, not rejected.
"""

import re
import unicodedata
from collections.abc import Iterator

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaExists, SigmaExpansion, SigmaNull, SigmaRegularExpression

from detectforge.harness.matcher import rule_fields
from detectforge.rules.parse import RuleError

FilterKey = tuple[str | None, str]


def dropped_fields(original: SigmaRule, candidate: SigmaRule) -> list[str]:
    return sorted(rule_fields(original) - rule_fields(candidate))


def dropped_filters(original: SigmaRule, candidate: SigmaRule) -> list[str]:
    """Exclusions of the original (field + value under a NOT) that the candidate no longer has."""
    missing = _filters(original) - _filters(candidate)
    return [f"{field or '<keyword>'}: {value}" for field, value in sorted(missing, key=str)]


def _filters(rule: SigmaRule) -> set[FilterKey]:
    found: set[FilterKey] = set()

    def walk(node: object, negated: bool) -> None:
        match node:
            case ConditionNOT(args=[arg]):
                walk(arg, not negated)
            case ConditionAND(args=args) | ConditionOR(args=args):
                for a in args:
                    walk(a, negated)
            case ConditionFieldEqualsValueExpression(field=field, value=value) if negated:
                found.update((field, v) for v in _values(value))
            case ConditionValueExpression(value=value) if negated:
                found.update((None, v) for v in _values(value))

    try:
        for condition in rule.detection.parsed_condition:
            walk(condition.parsed, negated=False)
    except SigmaError as e:
        raise RuleError(f"invalid condition: {e}") from e
    return found


def _values(value: object) -> list[str]:
    """A stable text key per value (some pySigma types have no stable str(), e.g. SigmaNull)."""
    if isinstance(value, SigmaExpansion):
        return [v for item in value.values for v in _values(item)]
    if isinstance(value, SigmaRegularExpression):
        return [f"re:{value.regexp}"]
    if isinstance(value, SigmaNull):
        return ["null"]
    if isinstance(value, SigmaExists):
        return [f"exists:{value.exists}"]
    if isinstance(value, SigmaCompareExpression):
        return [f"{value.op.name.lower()}:{value.number.number}"]
    return [str(value).lower()]


# ---- overfitting ----------------------------------------------------------------------------

_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|U([0-9a-fA-F]{8}))")
MIN_COPIED_LENGTH = 12
COMMAND_LINE_FIELDS = {"CommandLine", "ParentCommandLine", ""}  # "" = keyword detections


def unusual_characters(candidate_yaml: str, original_yaml: str | None = None) -> list[str]:
    """Non-ASCII characters in the candidate's detection values that the original didn't have."""
    new = _characters(candidate_yaml) - (_characters(original_yaml) if original_yaml else set())
    return [f"U+{ord(c):04X} {unicodedata.name(c, 'unnamed character')}" for c in sorted(new)]


def copied_literals(
    candidate_yaml: str, attack_command_lines: list[str], original_yaml: str | None = None
) -> list[str]:
    """New literal command-line values (not regexes) that appear verbatim in the attacks the agent saw.

    Only command-line fields (and keywords) count: naming the program (Image, OriginalFileName) is
    the most legitimate signal a rule has; copying an argument from a test attack (a task name, a
    test file path) is what doesn't generalize.
    """
    known = {v.lower() for _, v in _detection_values(original_yaml)} if original_yaml else set()
    seen = [c.lower() for c in attack_command_lines]
    copied = set()
    for key, value in _detection_values(candidate_yaml):
        field = key.split("|")[0]
        literal = value.strip("*")
        if field not in COMMAND_LINE_FIELDS or "|re" in key:
            continue
        if value.lower() in known or len(literal) < MIN_COPIED_LENGTH:
            continue
        if any(literal.lower() in line for line in seen):
            copied.add(literal)
    return sorted(copied)


def _characters(rule_yaml: str) -> set[str]:
    found = set()
    for _, value in _detection_values(rule_yaml):
        found.update(ch for ch in value if ord(ch) > 127)
        for match in _ESCAPE.finditer(value):
            code = int(next(g for g in match.groups() if g), 16)
            if code > 127:
                found.add(chr(code))
    return found


def _detection_values(rule_yaml: str) -> Iterator[tuple[str, str]]:
    """(field|modifiers, value) for every string value under detection (the condition excluded)."""
    try:
        detection = (yaml.safe_load(rule_yaml) or {}).get("detection") or {}
    except (yaml.YAMLError, AttributeError):
        return
    for name, block in detection.items():
        if name == "condition":
            continue
        yield from _walk(block, key="")


def _walk(node: object, key: str) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, str(k))
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, key)
    elif isinstance(node, str):
        yield key, node
