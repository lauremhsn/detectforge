"""Quality gate: deterministic accept/reject for a submitted rule.

The agent can only propose; this gate decides whether a proposal is good enough to reach a human
reviewer as "passed", or goes to review as "needs human review" with the failed checks listed.
"""

import yaml
from pydantic import BaseModel, Field

from detectforge.harness.compare import compare, evasion_resistance
from detectforge.harness.matcher import required_fields
from detectforge.harness.run import run
from detectforge.rules.convert import convert_rule
from detectforge.rules.lint import (
    copied_literals,
    dropped_fields,
    dropped_filters,
    short_bare_values,
    unusual_characters,
)
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
    # A non-blocking check is a warning for the reviewer: it never makes the gate fail.
    blocking: bool = True


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

    Every rule must be valid, convert to the deploy targets and not contain characters copied from
    the test attacks (copied literal strings are a warning only). With original_yaml (hardening),
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
    checks.extend(_not_overfitted(rule_yaml, events, original_yaml))
    card = run(rule_yaml, events)
    if not card.valid:  # valid Sigma, but the harness couldn't run it (e.g. a regex too slow)
        checks.append(
            GateCheck(name="evaluable", passed=False, detail=card.error or "could not be evaluated")
        )
        return GateResult(passed=False, checks=checks)
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
    benign = sum(1 for e in events if e.label == "benign")
    checks.append(  # "0 false alarms" on 0 benign events is untested, not clean
        GateCheck(
            name="false_alarms_tested",
            passed=benign > 0,
            blocking=False,
            detail=(
                f"false alarms checked on {benign} benign events"
                if benign
                else "warning: no benign events to test against, so the false-alarm checks below prove "
                "nothing; a rule that fires on harmless commands would still pass. Check the held-out "
                "false alarms before approving."
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
    return GateResult(passed=all(c.passed for c in checks if c.blocking), checks=checks)


def _not_overfitted(rule_yaml: str, events: list[Event], original_yaml: str | None) -> list[GateCheck]:
    """Memorising the test attacks instead of describing the behavior (see rules/lint.py)."""
    unusual = unusual_characters(rule_yaml, original_yaml)
    attacks = [e.command_line for e in events if e.label == "attack"]
    copied = copied_literals(rule_yaml, attacks, original_yaml)
    short = short_bare_values(rule_yaml, original_yaml)
    return [
        GateCheck(
            name="no_unusual_characters",
            passed=not unusual,
            detail=(
                "added characters real rules don't need (copied from the test attacks?): "
                + ", ".join(unusual)
                if unusual
                else "none added"
            ),
        ),
        GateCheck(
            name="no_copied_test_strings",
            passed=not copied,
            blocking=False,
            detail=(
                "warning, check these are general and not test-specific: " + "; ".join(copied)
                if copied
                else "none"
            ),
        ),
        GateCheck(
            name="no_short_bare_values",
            passed=not short,
            detail=(
                "too short to be specific, they match inside ordinary words (keep a delimiter, "
                "e.g. '/ru ' or ' -ru '): " + ", ".join(repr(v) for v in short)
                if short
                else "none added"
            ),
        ),
    ]


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
    newly_required = sorted(required_fields(candidate) - required_fields(original))
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
        _keeps_metadata(original_yaml, rule_yaml),
        GateCheck(
            name="no_new_required_fields",
            passed=not newly_required,
            blocking=False,
            detail=(
                f"warning: the rule now needs {', '.join(newly_required)} to fire; it stays silent on logs "
                "that don't record it (e.g. Windows Security 4688 instead of Sysmon)"
                if newly_required
                else "no new required fields"
            ),
        ),
    ]


METADATA_KEYS = ("id", "author", "date", "references")


def _keeps_metadata(original_yaml: str, rule_yaml: str) -> GateCheck:
    """Hardening changes detection logic, never who wrote the rule or what it cites.

    Found on a real run: the agent "corrected" a reference link to a URL that doesn't exist. A reviewer
    approving the detection logic could ship that unnoticed, so it blocks until restored.
    """
    original, candidate = yaml.safe_load(original_yaml) or {}, yaml.safe_load(rule_yaml) or {}
    changed = [k for k in METADATA_KEYS if original.get(k) != candidate.get(k)]
    return GateCheck(
        name="keeps_original_metadata",
        passed=not changed,
        detail=(
            f"changed {', '.join(changed)}: restore the original values "
            "(only the detection logic should change)"
            if changed
            else "id, author, date and references unchanged"
        ),
    )
