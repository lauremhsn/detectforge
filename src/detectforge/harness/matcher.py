"""Compile a pySigma rule into a predicate over Events.

Semantics follow the Sigma specification: string values match the whole field value,
case-insensitively, with * and ? wildcards (modifiers such as contains/endswith/windash/base64
are already expanded by pySigma into wildcards or value lists). Regular expressions use search
semantics. Keyword detections (no field) match if any event field contains the keyword.
Fields not in SIGMA_FIELD_MAP are treated as absent.
"""

import re
from collections.abc import Callable

import regex
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from detectforge.rules.parse import RuleError
from detectforge.schemas import SIGMA_FIELD_MAP, Event

EventPredicate = Callable[[Event], bool]
ValuePredicate = Callable[[str | None], bool]

REGEX_TIMEOUT_S = 1.0
_SAFE_REGEX_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: regex.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: regex.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: regex.DOTALL,
}


class RegexTimeout(RuleError):
    """A rule's regular expression is too slow to evaluate (raised while matching an event)."""


_COMPARE_OPS = {
    SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
    SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
    SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
    SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
    SigmaCompareExpression.CompareOperators.NEQ: lambda a, b: a != b,
}


def compile_rule(rule: SigmaRule) -> EventPredicate:
    """Return a predicate that is True when the rule fires on an event. Raises RuleError."""
    try:
        conditions = [_compile_node(c.parsed) for c in rule.detection.parsed_condition]
    except SigmaError as e:
        raise RuleError(f"invalid condition: {e}") from e
    return lambda event: any(c(event) for c in conditions)


def rule_fields(rule: SigmaRule) -> set[str]:
    """Sigma field names referenced by the rule's conditions."""
    fields: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            fields.add(node.field)
        for arg in getattr(node, "args", None) or []:
            walk(arg)

    try:
        for c in rule.detection.parsed_condition:
            walk(c.parsed)
    except SigmaError as e:
        raise RuleError(f"invalid condition: {e}") from e
    return fields


def can_fire(rule: SigmaRule) -> bool:
    """False if the rule can never match any event because it depends on fields events lack.

    Every check on a field missing from the event schema has a fixed outcome (the field is
    absent); every other check is treated as "could go either way". The verdict "can never
    fire" is therefore always correct; "can fire" may be optimistic for rules whose checks on
    known fields contradict each other.
    """
    return _can_fire_without(rule, frozenset())


def required_fields(rule: SigmaRule) -> set[str]:
    """Fields the rule can't fire without: if a log lacks one of them, the rule stays silent."""
    return {f for f in rule_fields(rule) if not _can_fire_without(rule, frozenset({f}))}


def _can_fire_without(rule: SigmaRule, absent: frozenset[str]) -> bool:
    try:
        return any(_possible(c.parsed, absent)[0] for c in rule.detection.parsed_condition)
    except SigmaError as e:
        raise RuleError(f"invalid condition: {e}") from e


def _possible(node: object, absent: frozenset[str]) -> tuple[bool, bool]:
    """(can be true, can be false) for a condition node, given which fields events have.

    Fields outside the event schema, and those in `absent`, are treated as missing from the log.
    """
    match node:
        case ConditionAND(args=args):
            parts = [_possible(a, absent) for a in args]
            return all(t for t, _ in parts), any(f for _, f in parts)
        case ConditionOR(args=args):
            parts = [_possible(a, absent) for a in args]
            return any(t for t, _ in parts), all(f for _, f in parts)
        case ConditionNOT(args=[arg]):
            t, f = _possible(arg, absent)
            return f, t
        case ConditionFieldEqualsValueExpression(field=field, value=value) if (
            field not in SIGMA_FIELD_MAP or field in absent
        ):
            fixed = _compile_value(value)(None)
            return fixed, not fixed
    return True, True


def _field_value(event: Event, field: str) -> str | None:
    attr = SIGMA_FIELD_MAP.get(field)
    return getattr(event, attr) if attr else None


def _compile_node(node: object) -> EventPredicate:
    match node:
        case ConditionAND(args=args):
            parts = [_compile_node(a) for a in args]
            return lambda e: all(p(e) for p in parts)
        case ConditionOR(args=args):
            parts = [_compile_node(a) for a in args]
            return lambda e: any(p(e) for p in parts)
        case ConditionNOT(args=[arg]):
            inner = _compile_node(arg)
            return lambda e: not inner(e)
        case ConditionFieldEqualsValueExpression(field=field, value=value):
            check = _compile_value(value)
            return lambda e: check(_field_value(e, field))
        case ConditionValueExpression(value=value):
            check = _compile_value(value, keyword=True)
            attrs = tuple(SIGMA_FIELD_MAP.values())
            return lambda e: any(check(getattr(e, a)) for a in attrs)
    raise RuleError(f"unsupported condition element: {type(node).__name__}")


def _compile_value(value: object, keyword: bool = False) -> ValuePredicate:
    if isinstance(value, SigmaExpansion):
        parts = [_compile_value(v, keyword) for v in value.values]
        return lambda v: any(p(v) for p in parts)
    if isinstance(value, SigmaString):
        pattern = _wildcard_regex(value)
        if keyword:
            pattern = f".*{pattern}.*"
        flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.DOTALL | re.IGNORECASE
        compiled = re.compile(pattern, flags)
        return lambda v: v is not None and compiled.fullmatch(v) is not None
    if isinstance(value, SigmaRegularExpression):
        return _compile_regex(value)
    if isinstance(value, SigmaNull):
        return lambda v: v is None
    if isinstance(value, SigmaExists):
        return lambda v: (v is not None) == value.exists
    if isinstance(value, SigmaNumber | SigmaBool):
        expected = str(value).lower()
        return lambda v: v is not None and v.strip().lower() == expected
    if isinstance(value, SigmaCompareExpression):
        op, bound = _COMPARE_OPS[value.op], value.number.number
        return lambda v: _as_number(v) is not None and op(_as_number(v), bound)
    raise RuleError(f"unsupported value type: {type(value).__name__}")


def _compile_regex(value: SigmaRegularExpression) -> ValuePredicate:
    """Rule regexes (often agent-written) run with a time limit.

    A pattern like (a|aa)+$ can take minutes on one command line ("catastrophic backtracking");
    without a limit, one bad rule would hang a whole batch of experiments. The `regex` module
    supports a timeout; the error names the pattern only, never the event.
    """
    pattern = str(value.regexp)
    flags = 0
    for flag in value.flags:
        flags |= _SAFE_REGEX_FLAGS[flag]
    try:
        compiled = regex.compile(pattern, flags)
    except regex.error as e:
        raise RuleError(f"invalid regular expression {pattern!r}: {e}") from e

    def check(v: str | None) -> bool:
        if v is None:
            return False
        try:
            return compiled.search(v, timeout=REGEX_TIMEOUT_S) is not None
        except TimeoutError:
            raise RegexTimeout(
                f"regular expression {pattern!r} took over {REGEX_TIMEOUT_S}s on one event "
                "(catastrophic backtracking); rewrite it without nested or overlapping repeats"
            ) from None

    return check


def _wildcard_regex(value: SigmaString) -> str:
    parts = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise RuleError("placeholders (|expand) are not supported")
    return "".join(parts)


def _as_number(v: str | None) -> float | None:
    try:
        return float(v) if v is not None else None
    except ValueError:
        return None
