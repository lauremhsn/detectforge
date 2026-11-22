"""Run an evaluation arm over the whole rule set and aggregate the per-rule metrics.

Arm 1 (community) scores each selected SigmaHQ rule unchanged. The agent arms (adapted, written) score
the rule the agent produced for each selection rule, pulled from its saved run by matching the provenance
setup_key (no model calls). All three go through the same scorer, so the three-arm comparison is
like-for-like: same events, same micro-averaging. A selection rule with no saved run counts as all-missed
(a real coverage gap), never silently dropped.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from detectforge.agent.batch import _completed_runs
from detectforge.agent.loop import AgentRun, Mode
from detectforge.agent.runner import run_provenance, scope_events
from detectforge.eval.metrics import MUTATED, RuleResult, score_from_card
from detectforge.harness.run import no_rule, run
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event, RuleSource, Split, Transform


class ArmCost(BaseModel):
    """What the agent spent on an arm; None for community (no model)."""

    accepted_rules: int  # runs the gate passed
    model_calls: int
    prompt_tokens: int
    completion_tokens: int
    duration_s: float
    calls_per_accepted_rule: float | None


class ArmResult(BaseModel):
    arm: RuleSource
    rule_count: int
    valid_rules: int
    overall_evasion_resistance: float | None
    resistance_by_transform: dict[Transform, float | None]
    resistance_by_mutation_split: dict[Split, float | None]
    resistance_by_selection_split: dict[str, float | None]
    false_alarm_rate: float | None  # micro over held-out benign events
    rules_fully_robust: int
    rules_evaded: int
    cost: ArmCost | None = None
    rules: list[RuleResult]


class ThreeArmComparison(BaseModel):
    """The headline: community vs agent-adapted vs agent-written, scored the same way."""

    community: ArmResult
    adapted: ArmResult
    written: ArmResult


@dataclass
class _Trial:
    event: Event
    detected: bool
    selection_split: str


@dataclass
class _Scored:
    results: list[RuleResult]
    trials: list[_Trial]
    fa_hits: int  # held-out benign events the arm's rules matched
    fa_total: int


def _micro(values: list[bool]) -> float | None:
    return sum(values) / len(values) if values else None


def _score_arm(selection: dict, events: list[Event], arm: RuleSource,
               rule_yaml_of: Callable[[dict], str | None]) -> _Scored:
    """Score every selection rule with the YAML rule_yaml_of returns (None = no rule, all missed)."""
    results: list[RuleResult] = []
    trials: list[_Trial] = []
    fa_hits = fa_total = 0
    for rule in selection["rules"]:
        rule_events = scope_events(events, rule["technique"], set(rule["base_attacks"]))
        rule_yaml = rule_yaml_of(rule)
        card = run(rule_yaml, rule_events) if rule_yaml else no_rule(rule_events)
        result = score_from_card(
            card, rule_events, rule_id=rule["id"], title=rule["title"],
            technique=rule["technique"], selection_split=rule["split"], source=arm,
        )
        if rule_yaml is None:  # no agent run produced a rule: a coverage gap, not a valid rule
            result = result.model_copy(update={"valid": False, "error": "no saved agent run"})
        results.append(result)
        matched = set(card.matched_event_ids)
        trials += [
            _Trial(e, e.event_id in matched, rule["split"])
            for e in rule_events if e.label == "attack" and e.transform != "none"
        ]
        heldout_benign = [e for e in rule_events if e.label == "benign" and e.split == "heldout"]
        fa_hits += sum(e.event_id in matched for e in heldout_benign)
        fa_total += len(heldout_benign)
    return _Scored(results, trials, fa_hits, fa_total)


def _arm_result(arm: RuleSource, s: _Scored, cost: ArmCost | None = None) -> ArmResult:
    def resistance(keep: Callable[[_Trial], bool]) -> float | None:
        return _micro([t.detected for t in s.trials if keep(t)])

    valid = [r for r in s.results if r.valid]
    return ArmResult(
        arm=arm,
        rule_count=len(s.results),
        valid_rules=len(valid),
        overall_evasion_resistance=_micro([t.detected for t in s.trials]),
        resistance_by_transform={tr: resistance(lambda t, tr=tr: t.event.transform == tr) for tr in MUTATED},
        resistance_by_mutation_split={
            sp: resistance(lambda t, sp=sp: t.event.split == sp) for sp in ("tune", "heldout")
        },
        resistance_by_selection_split={
            sp: resistance(lambda t, sp=sp: t.selection_split == sp) for sp in ("dev", "test")
        },
        false_alarm_rate=(s.fa_hits / s.fa_total) if s.fa_total else None,
        rules_fully_robust=sum(r.evasion_resistance == 1.0 for r in valid),
        rules_evaded=sum(bool(r.evaded_by) for r in valid),
        cost=cost,
        rules=s.results,
    )


def run_community_arm(selection: dict, index: ReferenceIndex, events: list[Event]) -> ArmResult:
    by_id = {r.id: r for r in index.rules}
    scored = _score_arm(selection, events, "community",
                        lambda rule: by_id[rule["id"]].rule_yaml if rule["id"] in by_id else None)
    return _arm_result("community", scored)


def run_agent_arm(selection: dict, index: ReferenceIndex, events: list[Event], runs_dir: Path,
                  model_name: str, *, mode: Mode) -> ArmResult:
    """Score the agent's rules for an arm. mode="harden" is adapted, "write" is written.

    Each selection rule is matched to its saved run by the same setup_key the batch computes (no model
    client needed), and its final_rule_yaml is re-scored on the held-out events.
    """
    by_id = {r.id: r for r in index.rules}
    done = _completed_runs(runs_dir)
    used: list[AgentRun] = []

    def final_yaml(rule: dict) -> str | None:
        ref = by_id.get(rule["id"])
        if mode == "harden" and ref is None:
            return None
        start = None if mode == "write" else ref.rule_yaml
        in_scope = scope_events(events, rule["technique"], set(rule["base_attacks"]))
        key = run_provenance(start, in_scope, None, model_name).setup_key
        runs = done.get(key, [])
        if not runs:
            return None
        used.append(runs[-1].run)  # the most recent run for this setup
        return runs[-1].run.final_rule_yaml or None

    arm: RuleSource = "written" if mode == "write" else "adapted"
    scored = _score_arm(selection, events, arm, final_yaml)
    return _arm_result(arm, scored, cost=_cost(used))


def _cost(runs: list[AgentRun]) -> ArmCost:
    accepted = sum(r.status == "passed" for r in runs)
    calls = sum(len(r.model_calls) for r in runs)
    return ArmCost(
        accepted_rules=accepted,
        model_calls=calls,
        prompt_tokens=sum(r.prompt_tokens for r in runs),
        completion_tokens=sum(r.completion_tokens for r in runs),
        duration_s=sum(r.duration_s for r in runs),
        calls_per_accepted_rule=(calls / accepted) if accepted else None,
    )


def three_arm_comparison(selection: dict, index: ReferenceIndex, events: list[Event], runs_dir: Path,
                         model_name: str) -> ThreeArmComparison:
    """All three arms from one selection + one runs dir (harden and write runs share it, keyed apart)."""
    return ThreeArmComparison(
        community=run_community_arm(selection, index, events),
        adapted=run_agent_arm(selection, index, events, runs_dir, model_name, mode="harden"),
        written=run_agent_arm(selection, index, events, runs_dir, model_name, mode="write"),
    )
