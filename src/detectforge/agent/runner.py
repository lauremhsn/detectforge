"""Run one hardening request end to end and save the evidence.

The split between agent and evaluation is enforced here: the agent gets the tuning split only;
the held-out split is scored afterwards, by deterministic code, and stored next to the run as
evaluation evidence for the human reviewer. The agent never sees it.
"""

import json
from pathlib import Path

from pydantic import BaseModel

from detectforge.agent.loop import AgentRun, harden
from detectforge.harness.compare import HardeningReport, compare
from detectforge.llm import ChatClient
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event


class HardeningOutcome(BaseModel):
    run: AgentRun
    heldout_evaluation: HardeningReport | None
    saved_to: str | None = None


def run_hardening(
    rule_yaml: str,
    technique: str,
    events: list[Event],
    client: ChatClient,
    model_name: str,
    index: ReferenceIndex | None = None,
    out_dir: Path | None = None,
) -> HardeningOutcome:
    """events may contain both splits; only the tuning part reaches the agent."""
    in_scope = [e for e in events if e.technique == technique]
    tuning = [e for e in in_scope if e.split == "tune"]
    heldout = [e for e in in_scope if e.split == "heldout"]
    if not any(e.label == "attack" for e in tuning):
        raise ValueError(f"no tuning attack events for {technique}")

    run = harden(rule_yaml, technique, tuning, client, model_name, index=index)
    evaluation = compare(rule_yaml, run.final_rule_yaml, heldout) if heldout else None
    outcome = HardeningOutcome(run=run, heldout_evaluation=evaluation)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{run.trace_id}.json"
        outcome.saved_to = str(path)
        path.write_text(json.dumps(outcome.model_dump(mode="json"), indent=2), encoding="utf-8")
        (out_dir / f"{run.trace_id}.yml").write_text(run.final_rule_yaml, encoding="utf-8")
    return outcome
