"""Evaluation regression gate: recomputed results must match the committed ones.

Arm 1 (community rules as-is) needs no model, so it is fully deterministic: the same code, rules and
events give the same numbers. CI recomputes it on every push and compares it with
data/eval/results/arm1_community.json. Any difference means a code change moved a reported number,
for example a matcher fix that changes which mutations a rule detects. That may be right, but it must
be deliberate: rerun `detectforge eval community` and commit the new results with the change, so the
pull request shows exactly which numbers moved and why.
"""

from typing import Any

from detectforge.eval.arms import ArmResult

TOLERANCE = 1e-9  # floating-point noise only; a real change in a rate is at least 1/len(trials)
MAX_SHOWN = 30


def diff_arm_results(expected: ArmResult, actual: ArmResult) -> list[str]:
    """Every difference, as 'path: expected -> actual'. Rules are matched by id, not position."""
    exp, act = expected.model_dump(mode="json"), actual.model_dump(mode="json")
    exp_rules = {r["rule_id"]: r for r in exp.pop("rules")}
    act_rules = {r["rule_id"]: r for r in act.pop("rules")}
    diffs = _diff(exp, act, "")
    for rule_id in sorted(exp_rules.keys() - act_rules.keys()):
        diffs.append(f"rules[{rule_id}]: missing from the recomputed results")
    for rule_id in sorted(act_rules.keys() - exp_rules.keys()):
        diffs.append(f"rules[{rule_id}]: new, not in the committed results")
    for rule_id in sorted(exp_rules.keys() & act_rules.keys()):
        diffs += _diff(exp_rules[rule_id], act_rules[rule_id], f"rules[{rule_id}]")
    return diffs


def _diff(expected: Any, actual: Any, path: str) -> list[str]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in sorted(expected.keys() | actual.keys(), key=str):
            sub = f"{path}.{key}" if path else str(key)
            if key not in actual:
                out.append(f"{sub}: removed")
            elif key not in expected:
                out.append(f"{sub}: added ({actual[key]!r})")
            else:
                out += _diff(expected[key], actual[key], sub)
        return out
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        return [
            d
            for i, (e, a) in enumerate(zip(expected, actual, strict=True))
            for d in _diff(e, a, f"{path}[{i}]")
        ]
    if _numbers(expected, actual) and abs(expected - actual) <= TOLERANCE:
        return []
    return [] if expected == actual else [f"{path}: {expected!r} -> {actual!r}"]


def _numbers(*values: Any) -> bool:
    return all(isinstance(v, int | float) and not isinstance(v, bool) for v in values)


def report(diffs: list[str]) -> str:
    shown = diffs[:MAX_SHOWN]
    more = f"\n  … and {len(diffs) - MAX_SHOWN} more" if len(diffs) > MAX_SHOWN else ""
    return "\n".join(f"  {d}" for d in shown) + more
