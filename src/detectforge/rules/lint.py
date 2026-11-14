"""Lint a hardened rule against its original: hardening may broaden a rule, never quietly narrow it.

Two things the harness cannot measure, so they are checked structurally instead:
- fields: every field the original used must still be used. Branches on fields our events lack
  (e.g. Hashes, Description) are untestable here; dropping them would lose real-world coverage
  without any score noticing.
- filters: every exclusion (a value under a NOT in the condition) must still be excluded. Dropping
  a filter for a known false positive would bring that false alarm back in production, and our
  hard negatives may not contain it.
"""

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
