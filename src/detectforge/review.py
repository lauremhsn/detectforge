"""Human review of agent runs: list them, open one, and record approve/reject decisions.

The agent only proposes; this is where a person decides. Each run lives in the runs directory as
<trace_id>.json (written by the runner). A decision is appended to <trace_id>.review.json (the full
history is kept, so a changed mind is visible), and an approved rule is copied to approved/, ready
to deploy. Nothing here calls the model.

Who may decide is checked here, not in the UI: `decide` takes a reviewer key, finds the reviewer it
belongs to (DETECTFORGE_REVIEWER_KEYS), and records that name. Typing a name proves nothing; a key
does. Repeated wrong keys lock decisions for a while, so keys can't be guessed by trying many.
"""

import hmac
import json
import logging
import re
import threading
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, ValidationError

from detectforge.agent.runner import HardeningOutcome
from detectforge.schemas import RuleRecord

log = logging.getLogger(__name__)

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
Decision = Literal["approved", "rejected"]

MIN_KEY_LENGTH = 16
MAX_FAILED_ATTEMPTS = 5  # wrong keys within LOCKOUT_S before decisions are refused
LOCKOUT_S = 60.0


class ReviewAuthError(Exception):
    """The decision was refused: approving is off, the key is wrong, or too many wrong keys."""


class ReviewDecision(BaseModel):
    decision: Decision
    reviewer: str = Field(min_length=1, max_length=80)
    comment: str = Field(default="", max_length=2000)
    decided_at: datetime


class RunSummary(BaseModel):
    trace_id: str
    created: datetime
    technique: str
    mode: str = "harden"
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
                mode=run.mode,
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


def latest_prompt_versions(runs: list[RunSummary]) -> set[str]:
    """The newest prompt version of each kind ("harden-v7", "write-v1"): v10 is newer than v9."""
    newest: dict[str, tuple[int, str]] = {}
    for r in runs:
        kind, _, number = r.prompt_version.rpartition("-v")
        rank = int(number) if number.isdigit() else -1
        if not kind:
            kind, rank = r.prompt_version, -1
        if kind not in newest or rank > newest[kind][0]:
            newest[kind] = (rank, r.prompt_version)
    return {version for _, version in newest.values()}


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


def parse_reviewer_keys(secret: SecretStr | None) -> dict[str, str]:
    """{key: reviewer name} from "name:key,name:key". Malformed or short keys are a config error."""
    if secret is None or not secret.get_secret_value().strip():
        return {}
    keys: dict[str, str] = {}
    for entry in secret.get_secret_value().split(","):
        name, sep, key = entry.strip().partition(":")
        name, key = name.strip(), key.strip()
        # Errors never repeat the value: it may be a key.
        if not sep or not name or len(name) > 80:
            raise ValueError("DETECTFORGE_REVIEWER_KEYS must look like name:key,name:key")
        if len(key) < MIN_KEY_LENGTH:
            raise ValueError(f"reviewer key for {name!r} is shorter than {MIN_KEY_LENGTH} characters")
        if key in keys:
            raise ValueError("two reviewers share the same key")
        keys[key] = name
    return keys


class _FailedAttempts:
    """Wrong keys seen recently, shared by every session of this process."""

    def __init__(self) -> None:
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def locked(self, now: float) -> bool:
        with self._lock:
            while self._times and now - self._times[0] > LOCKOUT_S:
                self._times.popleft()
            return len(self._times) >= MAX_FAILED_ATTEMPTS

    def add(self, now: float) -> None:
        with self._lock:
            self._times.append(now)

    def clear(self) -> None:
        with self._lock:
            self._times.clear()


_failed = _FailedAttempts()


def authenticate(keys: dict[str, str], presented: str, now: float | None = None) -> str:
    """The reviewer's name for this key, or ReviewAuthError. Compares in constant time."""
    now = time.monotonic() if now is None else now
    if not keys:
        raise ReviewAuthError("approving is off: no reviewer keys are set (DETECTFORGE_REVIEWER_KEYS)")
    if _failed.locked(now):
        raise ReviewAuthError("too many wrong reviewer keys; wait a minute and try again")
    candidate = presented.strip().encode()
    match = None
    for key, name in keys.items():  # check every key, so timing doesn't reveal which one was close
        if hmac.compare_digest(key.encode(), candidate):
            match = name
    if match is None:
        _failed.add(now)
        raise ReviewAuthError("wrong reviewer key")
    return match


def decide(
    runs_dir: Path,
    trace_id: str,
    decision: Decision,
    reviewer_key: str,
    keys: dict[str, str],
    comment: str = "",
) -> RuleRecord:
    """Record a decision by whoever the key belongs to: the only way the UI changes a rule's status."""
    reviewer = authenticate(keys, reviewer_key)
    return record_decision(runs_dir, trace_id, decision, reviewer, comment)


MIN_PREFIX_LENGTH = 6


def resolve_trace_id(runs_dir: Path, prefix: str) -> str:
    """The full trace id of the one saved run starting with prefix (as the list shows them)."""
    prefix = prefix.strip().lower()
    if len(prefix) < MIN_PREFIX_LENGTH or not re.fullmatch(r"[0-9a-f]+", prefix):
        raise ValueError(f"give at least {MIN_PREFIX_LENGTH} hex characters of the trace id")
    matches = sorted(p.stem for p in runs_dir.glob(f"{prefix}*.json") if _TRACE_ID.match(p.stem))
    if not matches:
        raise ValueError(f"no saved run starts with {prefix}")
    if len(matches) > 1:
        raise ValueError(f"{prefix} matches {len(matches)} runs; give more characters")
    return matches[0]


def _path(runs_dir: Path, trace_id: str, suffix: str) -> Path:
    """Only well-formed trace ids become file names, so input can't reach other paths."""
    if not _TRACE_ID.match(trace_id):
        raise ValueError(f"invalid trace id {trace_id!r}")
    return runs_dir / f"{trace_id}{suffix}"
