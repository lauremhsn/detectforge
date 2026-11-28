"""Run an evaluation arm over the whole rule set and aggregate the per-rule metrics.

Arm 1 (community) scores each selected SigmaHQ rule unchanged. The agent arms (adapted, written) score
the rule the agent produced for each selection rule, pulled from its saved runs by matching the provenance
setup_key (no model calls). All three go through the same scorer, so the three-arm comparison is
like-for-like: same events, same micro-averaging.

Agent arms use the REPEATS runs saved per rule: each run is scored on its own, and the arm's numbers are
the mean across runs with a min-max band (`spread`). For adapted, a selection rule the agent left alone
(no saved run) keeps its community rule -- the adapted rule set is {hardened weak rules} + {untouched
community rules}, so an untouched rule is the community rule, not a gap. For written, no saved run is a
real coverage gap (the agent failed to write a rule), all-missed.
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

REPEATS = 3  # runs wanted per rule (matches --repeat); fewer gets flagged, not silently averaged


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
    overall_evasion_resistance: float | None  # mean over the repeat runs
    resistance_by_transform: dict[Transform, float | None]
    resistance_by_mutation_split: dict[Split, float | None]
    resistance_by_selection_split: dict[str, float | None]
    false_alarm_rate: float | None  # micro over held-out benign events
    rules_fully_robust: int
    rules_evaded: int
    cost: ArmCost | None = None
    rules: list[RuleResult]
    spread: tuple[float, float] | None = None  # (min, max) overall across runs; None for community
    runs_per_rule: int | None = None  # None for community
    incomplete_rules: list[str] = []  # agent rules with 1..REPEATS-1 saved runs


class AdaptedEffect(BaseModel):
    """The agent's own lift: on just the rules it changed, community vs adapted (the rest it left alone)."""

    touched_rules: int
    community_resistance: float | None
    adapted_resistance: float | None


class ThreeArmComparison(BaseModel):
    """The headline: community vs agent-adapted vs agent-written, scored the same way."""

    community: ArmResult
    adapted: ArmResult
    written: ArmResult
    adapted_effect: AdaptedEffect | None = None


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


def _mean(values: list[float | None]) -> float | None:
    xs = [v for v in values if v is not None]
    return sum(xs) / len(xs) if xs else None


def _score_arm(
    selection: dict, events: list[Event], arm: RuleSource, rule_yaml_of: Callable[[dict], str | None]
) -> _Scored:
    """Score every selection rule with the YAML rule_yaml_of returns (None = no rule, all missed)."""
    results: list[RuleResult] = []
    trials: list[_Trial] = []
    fa_hits = fa_total = 0
    for rule in selection["rules"]:
        rule_events = scope_events(events, rule["technique"], set(rule["base_attacks"]))
        rule_yaml = rule_yaml_of(rule)
        card = run(rule_yaml, rule_events) if rule_yaml else no_rule(rule_events)
        result = score_from_card(
            card,
            rule_events,
            rule_id=rule["id"],
            title=rule["title"],
            technique=rule["technique"],
            selection_split=rule["split"],
            source=arm,
        )
        if rule_yaml is None:  # no rule to score: a coverage gap, not a valid rule
            result = result.model_copy(update={"valid": False, "error": "no saved agent run"})
        results.append(result)
        matched = set(card.matched_event_ids)
        trials += [
            _Trial(e, e.event_id in matched, rule["split"])
            for e in rule_events
            if e.label == "attack" and e.transform != "none"
        ]
        heldout_benign = [e for e in rule_events if e.label == "benign" and e.split == "heldout"]
        fa_hits += sum(e.event_id in matched for e in heldout_benign)
        fa_total += len(heldout_benign)
    return _Scored(results, trials, fa_hits, fa_total)


def _arm_result(arm: RuleSource, s: _Scored) -> ArmResult:
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
        rules=s.results,
    )


def run_community_arm(selection: dict, index: ReferenceIndex, events: list[Event]) -> ArmResult:
    by_id = {r.id: r for r in index.rules}
    scored = _score_arm(
        selection,
        events,
        "community",
        lambda rule: by_id[rule["id"]].rule_yaml if rule["id"] in by_id else None,
    )
    return _arm_result("community", scored)


def _rule_runs(
    selection: dict,
    by_id: dict,
    events: list[Event],
    model_name: str,
    done: dict,
    mode: Mode,
) -> dict[str, list[AgentRun]]:
    """Per rule id: its saved runs with a non-empty final rule, newest last."""
    out: dict[str, list[AgentRun]] = {}
    for rule in selection["rules"]:
        ref = by_id.get(rule["id"])
        if mode == "harden" and ref is None:
            out[rule["id"]] = []
            continue
        start = None if mode == "write" else ref.rule_yaml
        in_scope = scope_events(events, rule["technique"], set(rule["base_attacks"]))
        key = run_provenance(start, in_scope, None, model_name).setup_key
        out[rule["id"]] = [o.run for o in done.get(key, []) if (o.run.final_rule_yaml or "").strip()]
    return out


def run_agent_arm(
    selection: dict,
    index: ReferenceIndex,
    events: list[Event],
    runs_dir: Path,
    model_name: str,
    *,
    mode: Mode,
    repeats: int = REPEATS,
) -> ArmResult:
    """Score the agent's rules for an arm. mode="harden" is adapted, "write" is written.

    Each rule is matched to its saved runs by the same setup_key the batch computes (no model client). The
    arm is scored once per run; its numbers are the mean, with a min-max band. Adapted falls back to the
    community rule where the agent made no run; written treats that as a coverage gap.
    """
    by_id = {r.id: r for r in index.rules}
    runs_by_rule = _rule_runs(selection, by_id, events, model_name, _completed_runs(runs_dir), mode)
    arm: RuleSource = "written" if mode == "write" else "adapted"

    def yaml_at(rule: dict, slot: int) -> str | None:
        runs = runs_by_rule[rule["id"]]
        if runs:
            return runs[slot % len(runs)].final_rule_yaml or None  # cycle if fewer than repeats
        if mode == "harden":  # untouched rule stays the community rule
            ref = by_id.get(rule["id"])
            return ref.rule_yaml if ref else None
        return None  # written: no run is a real gap

    per_slot = [
        _arm_result(arm, _score_arm(selection, events, arm, lambda rule, i=i: yaml_at(rule, i)))
        for i in range(repeats)
    ]
    overalls = [a.overall_evasion_resistance for a in per_slot if a.overall_evasion_resistance is not None]
    spread = (min(overalls), max(overalls)) if overalls else None
    incomplete = sorted(rid for rid, runs in runs_by_rule.items() if 0 < len(runs) < repeats)
    cost = _cost([r for runs in runs_by_rule.values() for r in runs])
    return _combine(arm, per_slot, spread, repeats, incomplete, cost)


def _combine(
    arm: RuleSource,
    per_slot: list[ArmResult],
    spread: tuple[float, float] | None,
    repeats: int,
    incomplete: list[str],
    cost: ArmCost,
) -> ArmResult:
    """Mean the float metrics across runs; keep counts and per-rule detail from the run nearest the mean."""
    mean_overall = _mean([a.overall_evasion_resistance for a in per_slot])
    rep = min(per_slot, key=lambda a: abs((a.overall_evasion_resistance or 0.0) - (mean_overall or 0.0)))

    def mean_by(attr: str) -> dict:
        return {k: _mean([getattr(a, attr)[k] for a in per_slot]) for k in getattr(rep, attr)}

    return ArmResult(
        arm=arm,
        rule_count=rep.rule_count,
        valid_rules=rep.valid_rules,
        overall_evasion_resistance=mean_overall,
        resistance_by_transform=mean_by("resistance_by_transform"),
        resistance_by_mutation_split=mean_by("resistance_by_mutation_split"),
        resistance_by_selection_split=mean_by("resistance_by_selection_split"),
        false_alarm_rate=_mean([a.false_alarm_rate for a in per_slot]),
        rules_fully_robust=rep.rules_fully_robust,
        rules_evaded=rep.rules_evaded,
        cost=cost,
        rules=rep.rules,
        spread=spread,
        runs_per_rule=repeats,
        incomplete_rules=incomplete,
    )


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


def _adapted_effect(
    selection: dict, index: ReferenceIndex, events: list[Event], runs_dir: Path, model_name: str
) -> AdaptedEffect | None:
    """Community vs adapted on just the rules the agent actually hardened (ignores the untouched ones)."""
    by_id = {r.id: r for r in index.rules}
    runs = _rule_runs(selection, by_id, events, model_name, _completed_runs(runs_dir), "harden")
    touched = {"rules": [r for r in selection["rules"] if runs.get(r["id"])]}
    if not touched["rules"]:
        return None
    community = run_community_arm(touched, index, events)
    adapted = run_agent_arm(touched, index, events, runs_dir, model_name, mode="harden")
    return AdaptedEffect(
        touched_rules=len(touched["rules"]),
        community_resistance=community.overall_evasion_resistance,
        adapted_resistance=adapted.overall_evasion_resistance,
    )


def three_arm_comparison(
    selection: dict, index: ReferenceIndex, events: list[Event], runs_dir: Path, model_name: str
) -> ThreeArmComparison:
    """All three arms from one selection + one runs dir (harden and write runs share it, keyed apart)."""
    return ThreeArmComparison(
        community=run_community_arm(selection, index, events),
        adapted=run_agent_arm(selection, index, events, runs_dir, model_name, mode="harden"),
        written=run_agent_arm(selection, index, events, runs_dir, model_name, mode="write"),
        adapted_effect=_adapted_effect(selection, index, events, runs_dir, model_name),
    )
