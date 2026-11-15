"""Quality gate: deterministic accept/reject for a submitted rule.

The agent can only propose; this gate decides whether a proposal is good enough to reach a human
reviewer as "passed", or goes to review as "needs human review" with the failed checks listed.
"""

from pydantic import BaseModel, Field

from detectforge.harness.compare import compare, evasion_resistance
from detectforge.harness.run import run
from detectforge.rules.convert import convert_rule
from detectforge.rules.lint import dropped_fields, dropped_filters
from detectforge.rules.parse import load_rule
from detectforge.rules.validate import validate_rule
from detectforge.schemas import Event


class GateConfig(BaseModel):
    min_evasion_resistance: float = Field(default=0.8, ge=0, le=1)
    max_false_alarms: int = Field(default=0, ge=0)
    # The rule must convert to each of these SIEM query languages (pySigma Elastic backends).
    deploy_targets: list[str] = Field(default_factory=lambda: ["lucene"])


class GateCheck(BaseModel):
    name: str
    passed: bool
    detail: str


class GateResult(BaseModel):
    passed: bool
    checks: list[GateCheck]


def check(
    rule_yaml: str,
    events: list[Event],
    original_yaml: str | None = None,
    config: GateConfig | None = None,
) -> GateResult:
    """Run every check (no short-circuit) so the reviewer sees all the reasons at once.

    Every rule must be valid and convert to the deploy targets. With original_yaml (hardening),
    it must also not regress against the original: no attack it caught may be lost, no false alarm
    added, and no field or exclusion of the original dropped (those can't all be measured here).
    """
    config = config or GateConfig()
    checks: list[GateCheck] = []

    validation = validate_rule(rule_yaml)
    checks.append(
        GateCheck(name="valid", passed=validation.valid, detail="; ".join(validation.errors) or "ok")
    )
    if not validation.valid:
        return GateResult(passed=False, checks=checks)

    checks.append(_deployable(rule_yaml, config.deploy_targets))
    card = run(rule_yaml, events)
    base = card.per_transform["none"]
    checks.append(
        GateCheck(
            name="detects_unmutated_attacks",
            passed=base.misses == 0,
            detail=f"{base.hits}/{base.attacks} unmutated attacks detected",
        )
    )
    resistance = evasion_resistance(card)
    checks.append(
        GateCheck(
            name="evasion_resistance",
            passed=resistance is None or resistance >= config.min_evasion_resistance,
            detail=(
                "no mutated attacks to measure"
                if resistance is None
                else f"{resistance:.0%} (minimum {config.min_evasion_resistance:.0%})"
            ),
        )
    )

    if original_yaml is None:
        checks.append(
            GateCheck(
                name="false_alarms",
                passed=card.false_alarms <= config.max_false_alarms,
                detail=f"{card.false_alarms} (maximum {config.max_false_alarms})",
            )
        )
    else:
        report = compare(original_yaml, rule_yaml, events)
        checks.append(
            GateCheck(
                name="no_lost_attacks",
                passed=not report.lost_event_ids,
                detail=f"{len(report.lost_event_ids)} attacks the original caught are now missed",
            )
        )
        checks.append(
            GateCheck(
                name="no_new_false_alarms",
                passed=not report.new_false_alarm_event_ids,
                detail=(
                    f"{len(report.new_false_alarm_event_ids)} new false alarms "
                    f"({report.false_alarms_before} before, {report.false_alarms_after} after)"
                ),
            )
        )
        checks.extend(_keeps_original_scope(original_yaml, rule_yaml))
    return GateResult(passed=all(c.passed for c in checks), checks=checks)


def _deployable(rule_yaml: str, targets: list[str]) -> GateCheck:
    failures = []
    for target in targets:
        try:
            if not all(convert_rule(rule_yaml, target)):
                failures.append(f"{target}: empty query")
        except Exception as e:  # any backend failure means the rule can't be deployed as written
            failures.append(f"{target}: {e}")
    return GateCheck(
        name="deployable",
        passed=not failures,
        detail="; ".join(failures) or f"converts to {', '.join(targets)}",
    )


def _keeps_original_scope(original_yaml: str, rule_yaml: str) -> list[GateCheck]:
    """Hardening may broaden a rule, never quietly narrow what the harness can't measure."""
    original, candidate = load_rule(original_yaml), load_rule(rule_yaml)
    fields = dropped_fields(original, candidate)
    filters = dropped_filters(original, candidate)
    return [
        GateCheck(
            name="keeps_original_fields",
            passed=not fields,
            detail=f"dropped fields: {', '.join(fields)}" if fields else "all original fields still used",
        ),
        GateCheck(
            name="keeps_original_filters",
            passed=not filters,
            detail=f"dropped exclusions: {'; '.join(filters)}" if filters else "all original exclusions kept",
        ),
    ]
