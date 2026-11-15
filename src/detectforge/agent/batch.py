"""Harden every rule of an evaluation selection (e.g. the dev rules), one agent run per rule.

Reads the selection manifest (data/eval/selection.yml): each rule's SigmaHQ id, technique, split
(dev/test) and the base attacks it is meant to detect. A rule is skipped, without spending model
calls, when there is nothing to test (no mutated tuning attacks) or, by default, nothing to improve
(it already detects every tuning mutation). If the model becomes unavailable (e.g. the free daily
limit is reached), the batch stops instead of failing every remaining rule.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from detectforge.agent.runner import run_hardening, scope_events
from detectforge.harness.compare import evasion_resistance
from detectforge.harness.run import run
from detectforge.llm import ChatClient
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event
from detectforge.tracing import Tracer


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
    action: str  # "hardened", "skipped", "error"
    note: str = ""
    trace_id: str | None = None
    status: str | None = None
    tuning_before: float | None = None
    tuning_after: float | None = None
    heldout_before: float | None = None
    heldout_after: float | None = None
    model_calls: int = 0


def load_selection(path: Path) -> list[SelectedRule]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [SelectedRule.model_validate(r) for r in doc["rules"]]


def harden_selection(
    selection: list[SelectedRule],
    events: list[Event],
    index: ReferenceIndex,
    client: ChatClient,
    model_name: str,
    runs_dir: Path,
    tracer: Tracer | None = None,
    split: str = "dev",
    only_improvable: bool = True,
    limit: int | None = None,
) -> list[BatchItem]:
    by_id = {r.id: r for r in index.rules}
    items: list[BatchItem] = []
    attempted = 0
    for rule in (r for r in selection if r.split == split):
        item = BatchItem(rule_id=rule.id, title=rule.title, technique=rule.technique, action="skipped")
        items.append(item)
        reference = by_id.get(rule.id)
        if reference is None:
            item.action, item.note = "error", "rule not in the SigmaHQ index"
            continue
        bases = set(rule.base_attacks)
        tuning = [e for e in scope_events(events, rule.technique, bases) if e.split == "tune"]
        baseline = evasion_resistance(run(reference.rule_yaml, tuning))
        item.tuning_before = baseline
        if baseline is None:
            item.note = "no mutated tuning attacks to test"
            continue
        if only_improvable and baseline >= 1.0:
            item.note = "already detects every tuning mutation"
            continue
        if limit is not None and attempted >= limit:
            item.note = "batch limit reached"
            continue
        attempted += 1
        try:
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
            continue
        agent_run, heldout = outcome.run, outcome.heldout_evaluation
        item.action, item.trace_id, item.status = "hardened", agent_run.trace_id, agent_run.status
        item.tuning_after = agent_run.tuning_evasion_resistance_after
        item.heldout_before = heldout.evasion_resistance_before if heldout else None
        item.heldout_after = heldout.evasion_resistance_after if heldout else None
        item.model_calls = len(agent_run.model_calls)
        item.note = "; ".join(agent_run.reasons)
        if agent_run.model_calls and not agent_run.model_calls[-1].ok:
            item.note = f"stopped the batch: {item.note}"
            break  # the model is unavailable; later rules would fail the same way
    return items
