"""Harden every rule of an evaluation selection (e.g. the dev rules), one agent run per rule.

Reads the selection manifest (data/eval/selection.yml): each rule's SigmaHQ id, technique, split
(dev/test) and the base attacks it is meant to detect. A rule is skipped, without spending model
calls, when there is nothing to test (no mutated tuning attacks) or, by default, nothing to improve
(it already detects every tuning mutation). If the model becomes unavailable (e.g. the free daily
limit is reached), the batch stops instead of failing every remaining rule.

Saving the free quota (about 50 requests a day):
- runs are not repeated: a saved run with the exact same setup (prompt, model, budgets, code, rule and
  events; see provenance.py) counts toward `repeat`, so re-running a batch after it stopped only does
  what's missing. A run cut short because the model was unavailable doesn't count.
- `max_calls` caps the whole batch: a run is only started if its full budget still fits.
- `dry_run` shows the plan (which rules would run, worst-case number of calls) without the model.

`mode="write"` is the "agent-written" evaluation arm: for each selected rule, the agent writes a new
rule from scratch on the same events (that rule's base attacks), with every rule of the technique's
family hidden from its search. The community rule itself is never shown, so nothing is skipped as
"already detects every mutation"; the "before" is having no rule (0%).
"""

import logging
from collections import defaultdict
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from detectforge.agent.loop import Mode
from detectforge.agent.runner import (
    HardeningOutcome,
    run_hardening,
    run_provenance,
    run_writing,
    scope_events,
)
from detectforge.config import Settings, get_settings
from detectforge.harness.compare import evasion_resistance
from detectforge.harness.run import no_rule, run
from detectforge.llm import ChatClient
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event
from detectforge.tracing import Tracer

log = logging.getLogger(__name__)


class SelectedRule(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    title: str
    technique: str
    split: str
    base_attacks: list[str]


class BatchItem(BaseModel):
    rule_id: str
    title: str
    technique: str
    action: str  # "hardened", "written", "reused", "planned", "skipped", "error"
    note: str = ""
    trace_id: str | None = None
    status: str | None = None
    tuning_before: float | None = None
    tuning_after: float | None = None
    heldout_before: float | None = None
    heldout_after: float | None = None
    heldout_mutations: int = 0  # mutated held-out attacks for this rule; 0 = held-out resistance is n/a
    model_calls: int = 0  # spent by this batch (0 for a reused run)


def load_selection(path: Path) -> list[SelectedRule]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [SelectedRule.model_validate(r) for r in doc["rules"]]


def harden_selection(
    selection: list[SelectedRule],
    events: list[Event],
    index: ReferenceIndex,
    client: ChatClient | None,
    model_name: str,
    runs_dir: Path,
    tracer: Tracer | None = None,
    split: str = "dev",
    only_improvable: bool = True,
    limit: int | None = None,
    repeat: int = 1,
    max_calls: int | None = None,
    rule_ids: set[str] | None = None,
    dry_run: bool = False,
    settings: Settings | None = None,
    mode: Mode = "harden",
) -> list[BatchItem]:
    """One item per rule, or per run when repeat > 1. client may be None only for a dry run."""
    writing = mode == "write"
    if client is None and not dry_run:
        raise ValueError("a model client is needed unless dry_run is set")
    per_run = (settings or get_settings()).model_call_budget(mode)
    by_id = {r.id: r for r in index.rules}
    done = _completed_runs(runs_dir)
    items: list[BatchItem] = []
    started = 0
    reserved = 0  # calls spent by finished runs + the whole budget of a run about to start

    for rule in selection:
        if rule.split != split or (rule_ids is not None and rule.id not in rule_ids):
            continue

        def new_item(rule: SelectedRule = rule) -> BatchItem:
            item = BatchItem(rule_id=rule.id, title=rule.title, technique=rule.technique, action="skipped")
            items.append(item)
            return item

        reference = by_id.get(rule.id)
        if reference is None:
            item = new_item()
            item.action, item.note = "error", "rule not in the SigmaHQ index"
            continue
        bases = set(rule.base_attacks)
        in_scope = scope_events(events, rule.technique, bases)
        tuning = [e for e in in_scope if e.split == "tune"]
        start_rule = None if writing else reference.rule_yaml  # writing starts from no rule
        baseline = evasion_resistance(no_rule(tuning) if writing else run(reference.rule_yaml, tuning))
        # Hardening needs tuning variations to improve against. Writing doesn't: with none, the rule is
        # written from the base attacks alone (zero-shot) and reported as its own subset (eval/export).
        no_attacks = not any(e.label == "attack" for e in tuning)
        if (baseline is None and (not writing or no_attacks)) or (
            only_improvable and not writing and baseline is not None and baseline >= 1.0
        ):
            item = new_item()
            item.tuning_before = baseline
            item.note = (
                "no tuning attacks to write a rule from"
                if writing
                else "no mutated tuning attacks to test"
                if baseline is None
                else "already detects every tuning mutation"
            )
            continue

        setup = run_provenance(start_rule, in_scope, client, model_name).setup_key
        previous = done.get(setup, [])[:repeat]
        for earlier in previous:
            item = new_item()
            _fill(item, earlier, action="reused")
            item.model_calls = 0  # nothing spent now
            item.note = f"already run with this exact setup (saved run {earlier.run.trace_id[:8]})"

        for _ in range(repeat - len(previous)):
            item = new_item()
            item.tuning_before = baseline
            if limit is not None and started >= limit:
                item.note = "batch limit reached"
                continue
            if max_calls is not None and reserved + per_run > max_calls:
                item.note = (
                    f"not started: a run may use up to {per_run} calls, only {max_calls - reserved} "
                    f"of --max-calls {max_calls} left"
                )
                continue
            started += 1
            reserved += per_run
            if dry_run:
                item.action, item.note = "planned", f"would run (up to {per_run} model calls)"
                continue
            try:
                if writing:
                    outcome = run_writing(
                        rule.technique, events, client, model_name, index, runs_dir, tracer, base_ids=bases
                    )
                else:
                    outcome = run_hardening(
                        reference.rule_yaml,
                        rule.technique,
                        events,
                        client,
                        model_name,
                        index,
                        runs_dir,
                        tracer,
                        base_ids=bases,
                    )
            except ValueError as e:
                item.action, item.note = "error", str(e)
                reserved -= per_run  # rejected before any model call
                continue
            _fill(item, outcome, action="written" if writing else "hardened")
            reserved += item.model_calls - per_run  # count what the run spent, not its whole budget
            if _model_failed(outcome):
                item.note = f"stopped the batch: {item.note}"
                return items  # the model is unavailable; later rules would fail the same way
    return items


def _fill(item: BatchItem, outcome: HardeningOutcome, action: str) -> None:
    agent_run, heldout = outcome.run, outcome.heldout_evaluation
    item.action, item.trace_id, item.status = action, agent_run.trace_id, agent_run.status
    item.tuning_before = agent_run.tuning_evasion_resistance_before
    item.tuning_after = agent_run.tuning_evasion_resistance_after
    item.heldout_before = heldout.evasion_resistance_before if heldout else None
    item.heldout_after = heldout.evasion_resistance_after if heldout else None
    item.heldout_mutations = heldout.mutated_attacks if heldout else 0
    item.model_calls = len(agent_run.model_calls)
    item.note = "; ".join(agent_run.reasons)
    if heldout and heldout.new_false_alarm_event_ids:  # unseen by the agent and gate: flag for review
        new_fa = f"new held-out false alarms: {', '.join(heldout.new_false_alarm_event_ids)}"
        item.note = f"{item.note}; {new_fa}" if item.note else new_fa


class HeldoutSummary(BaseModel):
    """Held-out evasion resistance of a batch, averaged only over runs whose rule has held-out mutations.

    A rule whose attacks have no held-out mutation type (e.g. nothing to insert into or recode) has
    no held-out score: it is n/a, not 0% or 100%, and is left out of the mean instead of skewing it.
    """

    runs: int  # runs that ran or were reused (with --repeat, several per rule)
    runs_with_heldout: int
    rules: int  # distinct rules among those runs
    mean_before: float | None
    mean_after: float | None


def heldout_summary(items: list[BatchItem]) -> HeldoutSummary:
    ran = [i for i in items if i.action in ("hardened", "written", "reused")]
    scored = [i for i in ran if i.heldout_mutations > 0]

    def mean(values: list[float | None]) -> float | None:
        # A rule that couldn't be evaluated (invalid) detects nothing: it counts as 0, never dropped.
        return sum(v or 0.0 for v in values) / len(values) if values else None

    return HeldoutSummary(
        runs=len(ran),
        runs_with_heldout=len(scored),
        rules=len({i.rule_id for i in ran}),
        mean_before=mean([i.heldout_before for i in scored]),
        mean_after=mean([i.heldout_after for i in scored]),
    )


def _model_failed(outcome: HardeningOutcome) -> bool:
    calls = outcome.run.model_calls
    return bool(calls) and not calls[-1].ok


def _completed_runs(runs_dir: Path) -> dict[str, list[HardeningOutcome]]:
    """Saved runs by setup key, oldest first. Runs cut short by an unavailable model don't count."""
    found: dict[str, list[tuple[float, HardeningOutcome]]] = defaultdict(list)
    for path in sorted(runs_dir.glob("*.json")) if runs_dir.exists() else []:
        if path.name.endswith(".review.json"):
            continue
        try:
            outcome = HardeningOutcome.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            log.debug("ignoring %s: %s", path.name, type(e).__name__)
            continue
        if outcome.provenance is None or _model_failed(outcome):
            continue
        found[outcome.provenance.setup_key].append((path.stat().st_mtime, outcome))
    return {key: [o for _, o in sorted(runs, key=lambda r: r[0])] for key, runs in found.items()}
