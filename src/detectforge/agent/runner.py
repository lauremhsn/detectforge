"""Run one coverage request end to end and save the evidence.

Which path runs is decided here, by deterministic code, never by the model: harden the best usable
community rule for the technique, or, only when there is none, write a new rule (`cover`).

The split between agent and evaluation is enforced here: the agent gets the tuning split only;
the held-out split is scored afterwards, by deterministic code, and stored next to the run as
evaluation evidence for the human reviewer. The agent never sees it.
"""

import json
from pathlib import Path

from pydantic import BaseModel

from detectforge.agent.loop import AgentRun, Mode, harden, prompt_version, write_rule
from detectforge.config import get_settings
from detectforge.harness.compare import HardeningReport, compare
from detectforge.llm import ChatClient
from detectforge.provenance import Provenance, make_provenance
from detectforge.reference.index import MAX_LIMIT, ReferenceIndex, ReferenceRule
from detectforge.schemas import Event
from detectforge.tracing import NoopTracer, Tracer


class HardeningOutcome(BaseModel):
    run: AgentRun
    heldout_evaluation: HardeningReport | None
    saved_to: str | None = None
    trace_url: str | None = None
    # Which prompt, model, budgets, code and data produced this run (None in older run files).
    provenance: Provenance | None = None


def scope_events(events: list[Event], technique: str, base_ids: set[str] | None = None) -> list[Event]:
    """The events one rule is scored on.

    Attacks: the rule's technique, and if base_ids is given only those base attacks and their
    mutations (two rules for one technique can target different behaviors; testing a rule on the
    other's attacks would push it to broaden beyond its intent).

    Benign events: all of them, whatever technique they were collected for. A legitimate command is
    a false alarm for any rule that fires on it (e.g. `reg query ...\\Run /v X`, collected for registry
    dumping, must not trigger a Run-key persistence rule either).
    """
    return [
        e
        for e in events
        if e.label == "benign" or (e.technique == technique and (base_ids is None or e.base_id in base_ids))
    ]


def run_provenance(
    rule_yaml: str | None, in_scope: list[Event], client: ChatClient | None, model_name: str
) -> Provenance:
    """The setup an agent run on these (in-scope) events would have; rule_yaml None = writing."""
    settings = get_settings()
    fallback = getattr(client, "fallback_model", settings.fallback_model)  # client is None in a dry run
    mode: Mode = "harden" if rule_yaml is not None else "write"
    return make_provenance(rule_yaml or "", in_scope, model_name, fallback, prompt_version(mode), settings)


def find_usable_rule(index: ReferenceIndex | None, technique: str) -> ReferenceRule | None:
    """The community rule to harden: the best-ranked usable rule tagged with exactly this technique.

    Rules of a parent or sibling technique (e.g. T1053 for T1053.005) don't count: they target a
    different behavior, so hardening one would not cover this technique. None means "write a new rule".
    """
    if index is None:
        return None
    hits = index.search(technique, limit=MAX_LIMIT)
    return next((h.rule for h in hits if h.match == "technique" and h.rule.usable), None)


def cover(
    technique: str,
    events: list[Event],
    client: ChatClient,
    model_name: str,
    index: ReferenceIndex | None,
    out_dir: Path | None = None,
    tracer: Tracer | None = None,
    base_ids: set[str] | None = None,
) -> HardeningOutcome:
    """The pipeline for one technique: harden a usable community rule, or write one if none exists."""
    rule = find_usable_rule(index, technique)
    return _run_agent(
        rule.rule_yaml if rule else None,
        technique,
        events,
        client,
        model_name,
        index,
        out_dir,
        tracer,
        base_ids,
    )


def run_writing(
    technique: str,
    events: list[Event],
    client: ChatClient,
    model_name: str,
    index: ReferenceIndex | None = None,
    out_dir: Path | None = None,
    tracer: Tracer | None = None,
    base_ids: set[str] | None = None,
) -> HardeningOutcome:
    """Write a new rule whatever the index holds (the "agent-written" evaluation arm)."""
    return _run_agent(None, technique, events, client, model_name, index, out_dir, tracer, base_ids)


def run_hardening(
    rule_yaml: str,
    technique: str,
    events: list[Event],
    client: ChatClient,
    model_name: str,
    index: ReferenceIndex | None = None,
    out_dir: Path | None = None,
    tracer: Tracer | None = None,
    base_ids: set[str] | None = None,
) -> HardeningOutcome:
    """events may contain both splits; only the tuning part reaches the agent (see scope_events)."""
    return _run_agent(rule_yaml, technique, events, client, model_name, index, out_dir, tracer, base_ids)


def _run_agent(
    rule_yaml: str | None,
    technique: str,
    events: list[Event],
    client: ChatClient,
    model_name: str,
    index: ReferenceIndex | None,
    out_dir: Path | None,
    tracer: Tracer | None,
    base_ids: set[str] | None,
) -> HardeningOutcome:
    in_scope = scope_events(events, technique, base_ids)
    tuning = [e for e in in_scope if e.split == "tune"]
    heldout = [e for e in in_scope if e.split == "heldout"]
    if not any(e.label == "attack" for e in tuning):
        raise ValueError(
            f"no tuning attack events for {technique}" + (" and these base attacks" if base_ids else "")
        )

    tracer = tracer or NoopTracer()
    provenance = run_provenance(rule_yaml, in_scope, client, model_name)
    if rule_yaml is None:
        run = write_rule(technique, tuning, client, model_name, index=index, tracer=tracer)
    else:
        run = harden(rule_yaml, technique, tuning, client, model_name, index=index, tracer=tracer)
    tracer.flush()  # short-lived CLI runs must export before exiting
    # A written rule is compared with having no rule (0% before); "no rule produced" scores 0% after.
    evaluation = compare(rule_yaml, run.final_rule_yaml, heldout) if heldout else None
    # Evaluation on held-out data happens outside the traced run and is never sent to the tracer.
    outcome = HardeningOutcome(
        run=run,
        heldout_evaluation=evaluation,
        trace_url=tracer.trace_url(run.trace_id),
        provenance=provenance,
    )
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{run.trace_id}.json"
        outcome.saved_to = str(path)
        path.write_text(json.dumps(outcome.model_dump(mode="json"), indent=2), encoding="utf-8")
        (out_dir / f"{run.trace_id}.yml").write_text(run.final_rule_yaml, encoding="utf-8")
    return outcome
