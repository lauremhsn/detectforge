"""Harness: replay one Sigma rule against labeled events and score it."""

from collections import Counter

from detectforge.harness.matcher import compile_rule
from detectforge.rules.parse import RuleError, load_rule
from detectforge.schemas import TRANSFORMS, Event, Scorecard, TransformBreakdown


def run(rule_yaml: str, events: list[Event]) -> Scorecard:
    """Score a rule. Rule problems give valid=False; malformed event input raises ValueError.

    Error messages describe only the rule, never event contents, so a scorecard on a held-out
    split leaks nothing beyond its counts.
    """
    duplicates = [i for i, n in Counter(e.event_id for e in events).items() if n > 1]
    if duplicates:
        raise ValueError(f"{len(duplicates)} duplicate event_id(s) in input")

    try:
        matches = compile_rule(load_rule(rule_yaml))
    except RuleError as e:
        return Scorecard(valid=False, error=str(e))

    per_transform = {t: TransformBreakdown() for t in TRANSFORMS}
    matched_ids = []
    for event in events:
        bucket = per_transform[event.transform]
        fired = matches(event)
        if fired:
            matched_ids.append(event.event_id)
        if event.label == "attack":
            bucket.attacks += 1
            bucket.hits += fired
            bucket.misses += not fired
        else:
            bucket.benign += 1
            bucket.false_alarms += fired

    return Scorecard(
        valid=True,
        hits=sum(b.hits for b in per_transform.values()),
        misses=sum(b.misses for b in per_transform.values()),
        false_alarms=sum(b.false_alarms for b in per_transform.values()),
        matched_event_ids=matched_ids,
        per_transform=per_transform,
    )
