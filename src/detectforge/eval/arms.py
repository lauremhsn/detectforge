"""Run an evaluation arm over the whole rule set and aggregate the per-rule metrics.

Arm 1 (community) scores each selected SigmaHQ rule, unchanged, against its technique's base attacks and
their mutations. Aggregates are micro-averaged over rule x mutated-event trials, so a technique with more
rules or more mutations weighs proportionally. The agent-adapted and agent-written arms reuse this with
rules the agent produced.
"""

from dataclasses import dataclass

from pydantic import BaseModel

from detectforge.eval.metrics import MUTATED, RuleResult, score_from_card
from detectforge.harness.run import run
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event, RuleSource, Split, Transform


class ArmResult(BaseModel):
    arm: RuleSource
    rule_count: int
    valid_rules: int
    overall_evasion_resistance: float | None
    resistance_by_transform: dict[Transform, float | None]
    resistance_by_mutation_split: dict[Split, float | None]
    resistance_by_selection_split: dict[str, float | None]
    rules_fully_robust: int
    rules_evaded: int
    rules: list[RuleResult]


@dataclass
class _Trial:
    event: Event
    detected: bool
    selection_split: str


def _micro(values: list[bool]) -> float | None:
    return sum(values) / len(values) if values else None


def run_community_arm(selection: dict, index: ReferenceIndex, events: list[Event]) -> ArmResult:
    by_id = {r.id: r for r in index.rules}
    by_base: dict[str, list[Event]] = {}
    for event in events:
        by_base.setdefault(event.base_id, []).append(event)

    results: list[RuleResult] = []
    trials: list[_Trial] = []
    for rule in selection["rules"]:
        rule_events = [e for base in rule["base_attacks"] for e in by_base.get(base, [])]
        ref = by_id[rule["id"]]
        card = run(ref.rule_yaml, rule_events)
        results.append(
            score_from_card(
                card,
                rule_events,
                rule_id=rule["id"],
                title=rule["title"],
                technique=rule["technique"],
                selection_split=rule["split"],
                source="community",
            )
        )
        matched = set(card.matched_event_ids)
        trials += [
            _Trial(e, e.event_id in matched, rule["split"])
            for e in rule_events
            if e.label == "attack" and e.transform != "none"
        ]

    def resistance(keep) -> float | None:
        return _micro([t.detected for t in trials if keep(t)])

    valid = [r for r in results if r.valid]
    return ArmResult(
        arm="community",
        rule_count=len(results),
        valid_rules=len(valid),
        overall_evasion_resistance=_micro([t.detected for t in trials]),
        resistance_by_transform={tr: resistance(lambda t, tr=tr: t.event.transform == tr) for tr in MUTATED},
        resistance_by_mutation_split={
            s: resistance(lambda t, s=s: t.event.split == s) for s in ("tune", "heldout")
        },
        resistance_by_selection_split={
            s: resistance(lambda t, s=s: t.selection_split == s) for s in ("dev", "test")
        },
        rules_fully_robust=sum(r.evasion_resistance == 1.0 for r in valid),
        rules_evaded=sum(bool(r.evaded_by) for r in valid),
        rules=results,
    )
