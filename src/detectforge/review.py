"""Human review of agent runs: list them, open one, and record approve/reject decisions.

The agent only proposes; this is where a person decides. Each run lives in the runs directory as
<trace_id>.json (written by the runner). A decision is appended to <trace_id>.review.json (the full
history is kept, so a changed mind is visible), and an approved rule is copied to approved/, ready
to deploy. Nothing here calls the model.
"""

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from detectforge.agent.runner import HardeningOutcome
from detectforge.schemas import RuleRecord

log = logging.getLogger(__name__)

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
Decision = Literal["approved", "rejected"]


class ReviewDecision(BaseModel):
    decision: Decision
    reviewer: str = Field(min_length=1, max_length=80)
    comment: str = Field(default="", max_length=2000)
    decided_at: datetime


class RunSummary(BaseModel):
    trace_id: str
    created: datetime
    technique: str
    model: str
    prompt_version: str
    status: str
    final_source: str
    tuning_before: float | None
    tuning_after: float | None
    heldout_before: float | None
    heldout_after: float | None
    model_calls: int
    tokens: int
    decision: ReviewDecision | None


def list_runs(runs_dir: Path) -> list[RunSummary]:
    """Every saved run, newest first. Unreadable files are skipped (and logged), never fatal."""
    summaries = []
    for path in runs_dir.glob("*.json"):
        if not _TRACE_ID.match(path.stem):
            continue  # review files and anything else that isn't a run
        try:
            outcome = HardeningOutcome.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as e:
            log.warning("skipping unreadable run %s: %s", path.name, type(e).__name__)
            continue
        run, heldout = outcome.run, outcome.heldout_evaluation
        history = decisions(runs_dir, run.trace_id)
        summaries.append(
            RunSummary(
                trace_id=run.trace_id,
                created=datetime.fromtimestamp(path.stat().st_mtime, tz=UTC),
                technique=run.technique,
                model=run.model,
                prompt_version=run.prompt_version,
                status=run.status,
                final_source=run.final_source,
                tuning_before=run.tuning_evasion_resistance_before,
                tuning_after=run.tuning_evasion_resistance_after,
                heldout_before=heldout.evasion_resistance_before if heldout else None,
                heldout_after=heldout.evasion_resistance_after if heldout else None,
                model_calls=len(run.model_calls),
                tokens=run.prompt_tokens + run.completion_tokens,
                decision=history[-1] if history else None,
            )
        )
    return sorted(summaries, key=lambda s: s.created, reverse=True)


def calls_today(runs_dir: Path, now: datetime | None = None) -> int:
    """Model calls in the runs saved today (UTC, when OpenRouter's daily free limit resets)."""
    today = (now or datetime.now(UTC)).date()
    return sum(r.model_calls for r in list_runs(runs_dir) if r.created.astimezone(UTC).date() == today)


def load_run(runs_dir: Path, trace_id: str) -> HardeningOutcome:
    return HardeningOutcome.model_validate_json(
        _path(runs_dir, trace_id, ".json").read_text(encoding="utf-8")
    )


def decisions(runs_dir: Path, trace_id: str) -> list[ReviewDecision]:
    path = _path(runs_dir, trace_id, ".review.json")
    if not path.exists():
        return []
    try:
        return [ReviewDecision.model_validate(d) for d in json.loads(path.read_text(encoding="utf-8"))]
    except (OSError, ValueError, ValidationError) as e:
        log.warning("unreadable review file for %s: %s", trace_id, type(e).__name__)
        return []


def record_decision(
    runs_dir: Path, trace_id: str, decision: Decision, reviewer: str, comment: str = ""
) -> RuleRecord:
    """Append a decision; returns the rule record with its new status."""
    outcome = load_run(runs_dir, trace_id)  # also proves the run exists
    entry = ReviewDecision(
        decision=decision, reviewer=reviewer.strip(), comment=comment.strip(), decided_at=datetime.now(UTC)
    )
    history = [*decisions(runs_dir, trace_id), entry]
    _path(runs_dir, trace_id, ".review.json").write_text(
        json.dumps([d.model_dump(mode="json") for d in history], indent=2), encoding="utf-8"
    )
    approved_copy = runs_dir / "approved" / f"{trace_id}.yml"
    if decision == "approved":
        approved_copy.parent.mkdir(parents=True, exist_ok=True)
        approved_copy.write_text(outcome.run.final_rule_yaml, encoding="utf-8")
    elif approved_copy.exists():
        approved_copy.unlink()  # a later rejection withdraws the approval
    return outcome.run.record.model_copy(update={"status": decision})


def _path(runs_dir: Path, trace_id: str, suffix: str) -> Path:
    """Only well-formed trace ids become file names, so input can't reach other paths."""
    if not _TRACE_ID.match(trace_id):
        raise ValueError(f"invalid trace id {trace_id!r}")
    return runs_dir / f"{trace_id}{suffix}"
