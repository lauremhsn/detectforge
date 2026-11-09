"""Before/after comparison of two versions of the same rule on the same events.

This is the headline result: evasion resistance of a community rule as-is vs after hardening.
Evasion resistance counts mutated attack events only (transform != "none"); detection of the
unmutated base events is reported separately in per_transform["none"].

Reports list event ids (never event contents). On a held-out split they are for the evaluator
and the human reviewer only and must not be handed to the agent.
"""

from pydantic import BaseModel

from detectforge.harness.run import run
from detectforge.schemas import TRANSFORMS, Event, Scorecard, Transform


class TransformDelta(BaseModel):
    attacks: int
    hits_before: int
    hits_after: int
    resistance_before: float | None
    resistance_after: float | None
    benign: int
    false_alarms_before: int
    false_alarms_after: int


class HardeningReport(BaseModel):
    valid: bool
    before: Scorecard
    after: Scorecard
    mutated_attacks: int
    evasion_resistance_before: float | None
    evasion_resistance_after: float | None
    evasion_resistance_delta: float | None
    false_alarms_before: int
    false_alarms_after: int
    per_transform: dict[Transform, TransformDelta]
    newly_detected_event_ids: list[str]
    lost_event_ids: list[str]
    new_false_alarm_event_ids: list[str]
    removed_false_alarm_event_ids: list[str]


def compare(before_yaml: str, after_yaml: str, events: list[Event]) -> HardeningReport:
    """Score both rule versions on the same events and report what changed.

    valid is False if either version could not be evaluated; then resistance values are None.
    """
    before, after = run(before_yaml, events), run(after_yaml, events)
    valid = before.valid and after.valid
    matched_before, matched_after = set(before.matched_event_ids), set(after.matched_event_ids)

    def changed(label: str, gained: bool) -> list[str]:
        a, b = (matched_before, matched_after) if gained else (matched_after, matched_before)
        return [e.event_id for e in events if e.label == label and e.event_id in b - a]

    mutated_attacks = sum(e.label == "attack" and e.transform != "none" for e in events)
    resistance_before = _mutation_resistance(before, mutated_attacks) if valid else None
    resistance_after = _mutation_resistance(after, mutated_attacks) if valid else None

    return HardeningReport(
        valid=valid,
        before=before,
        after=after,
        mutated_attacks=mutated_attacks,
        evasion_resistance_before=resistance_before,
        evasion_resistance_after=resistance_after,
        evasion_resistance_delta=(
            resistance_after - resistance_before
            if resistance_before is not None and resistance_after is not None
            else None
        ),
        false_alarms_before=before.false_alarms,
        false_alarms_after=after.false_alarms,
        per_transform={t: _transform_delta(before, after, t, events, valid) for t in TRANSFORMS},
        newly_detected_event_ids=changed("attack", gained=True),
        lost_event_ids=changed("attack", gained=False),
        new_false_alarm_event_ids=changed("benign", gained=True),
        removed_false_alarm_event_ids=changed("benign", gained=False),
    )


def _mutation_resistance(card: Scorecard, mutated_attacks: int) -> float | None:
    if not mutated_attacks:
        return None
    return sum(card.per_transform[t].hits for t in TRANSFORMS if t != "none") / mutated_attacks


def _transform_delta(
    before: Scorecard, after: Scorecard, t: Transform, events: list[Event], valid: bool
) -> TransformDelta:
    b, a = before.per_transform[t], after.per_transform[t]
    attacks = sum(e.transform == t and e.label == "attack" for e in events)
    benign = sum(e.transform == t and e.label == "benign" for e in events)
    resistance = (lambda c: c.hits / attacks) if valid and attacks else (lambda c: None)
    return TransformDelta(
        attacks=attacks,
        hits_before=b.hits,
        hits_after=a.hits,
        resistance_before=resistance(b),
        resistance_after=resistance(a),
        benign=benign,
        false_alarms_before=b.false_alarms,
        false_alarms_after=a.false_alarms,
    )
