"""Metrics for one rule against its attack events and their mutations.

Evasion resistance is the harness definition (fraction of mutated attack events still detected); this
module breaks it down by transform type, by mutation split (tune/heldout), and reports which transforms
evade the rule. False-alarm rate is over benign events (hard negatives) when any are supplied.
"""

from collections.abc import Callable

from pydantic import BaseModel

from detectforge.harness.compare import evasion_resistance
from detectforge.harness.run import run
from detectforge.schemas import TRANSFORMS, Event, RuleSource, Scorecard, Split, Transform

MUTATED = [t for t in TRANSFORMS if t != "none"]


class RuleResult(BaseModel):
    rule_id: str
    title: str
    technique: str
    selection_split: str  # dev or test, from the rule set
    source: RuleSource
    valid: bool
    error: str | None
    base_detected: int
    base_total: int
    evasion_resistance: float | None
    resistance_by_transform: dict[Transform, float | None]
    resistance_by_mutation_split: dict[Split, float | None]
    evaded_by: list[Transform]
    false_alarm_rate: float | None


def _resistance(card: Scorecard, events: list[Event], keep: Callable[[Event], bool]) -> float | None:
    """Fraction of the selected mutated attack events the rule detects, or None if none are selected."""
    matched = set(card.matched_event_ids)
    subset = [e for e in events if e.label == "attack" and e.transform != "none" and keep(e)]
    return sum(e.event_id in matched for e in subset) / len(subset) if subset else None


def score_from_card(
    card: Scorecard,
    events: list[Event],
    *,
    rule_id: str,
    title: str,
    technique: str,
    selection_split: str,
    source: RuleSource,
) -> RuleResult:
    """Build a RuleResult from an already-computed scorecard (so the harness runs once per rule)."""
    matched = set(card.matched_event_ids)
    base = [e for e in events if e.label == "attack" and e.transform == "none"]
    benign = [e for e in events if e.label == "benign"]
    by_transform = {t: _resistance(card, events, lambda e, t=t: e.transform == t) for t in MUTATED}

    return RuleResult(
        rule_id=rule_id,
        title=title,
        technique=technique,
        selection_split=selection_split,
        source=source,
        valid=card.valid,
        error=card.error,
        base_detected=sum(e.event_id in matched for e in base),
        base_total=len(base),
        evasion_resistance=evasion_resistance(card) if card.valid else None,
        resistance_by_transform=by_transform,
        resistance_by_mutation_split={
            s: _resistance(card, events, lambda e, s=s: e.split == s) for s in ("tune", "heldout")
        },
        evaded_by=[t for t, r in by_transform.items() if r is not None and r < 1.0],
        false_alarm_rate=(card.false_alarms / len(benign)) if benign else None,
    )


def score_rule(rule_yaml: str, events: list[Event], **meta) -> RuleResult:
    return score_from_card(run(rule_yaml, events), events, **meta)
