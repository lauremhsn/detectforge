"""Provenance: exactly which setup produced a run, so every reported number can be traced back.

A run's result depends on the prompt, the model, the budgets, the code (gate, tools, harness), the
rule it started from and the events it was scored on. All of these are fingerprinted and saved with
the run. Two runs with the same `setup_key` were produced by the same setup, which lets a batch
skip work it has already done (saving the free model quota) and lets the evaluation group repeated
runs (3 per configuration) without mixing in results from an older prompt or dataset.

The git commit is saved too, for humans, but isn't part of the key: a commit that only touches the
docs or the UI doesn't change any result. The code fingerprint covers what does.
"""

import hashlib
import json
import subprocess
from pathlib import Path

from pydantic import BaseModel

from detectforge.config import Settings
from detectforge.schemas import Event

PACKAGE_DIR = Path(__file__).resolve().parent
# Code that can't change a run's result: the UI only displays runs.
_NOT_RESULT_CODE = {"ui"}


class Provenance(BaseModel):
    prompt_version: str
    model: str
    fallback_model: str | None
    budgets: dict[str, int]
    code_sha: str
    rule_sha: str
    events_sha: str
    event_count: int
    git_commit: str | None = None
    git_dirty: bool | None = None

    @property
    def setup_key(self) -> str:
        """Everything that can change the result (so: not the git commit)."""
        fields = self.model_dump(exclude={"git_commit", "git_dirty"})
        return _sha(json.dumps(fields, sort_keys=True).encode())


def make_provenance(
    rule_yaml: str,
    events: list[Event],
    model: str,
    fallback_model: str | None,
    prompt_version: str,
    settings: Settings,
) -> Provenance:
    commit, dirty = git_state()
    return Provenance(
        prompt_version=prompt_version,
        model=model,
        fallback_model=fallback_model,
        budgets={
            "model_calls": settings.model_call_budget(
                "write" if prompt_version.startswith("write") else "harden"
            ),
            "tuning_runs": settings.max_iterations,
            "tokens": settings.max_tokens_per_rule,
            "output_tokens": settings.max_output_tokens,
        },
        code_sha=code_fingerprint(),
        rule_sha=_sha(_normalize(rule_yaml.encode("utf-8"))),
        events_sha=events_fingerprint(events),
        event_count=len(events),
        git_commit=commit,
        git_dirty=dirty,
    )


def events_fingerprint(events: list[Event]) -> str:
    """Order-independent: the same events in another order are the same data."""
    lines = sorted(json.dumps(e.model_dump(mode="json"), sort_keys=True) for e in events)
    return _sha("\n".join(lines).encode("utf-8"))


def code_fingerprint(package_dir: Path = PACKAGE_DIR) -> str:
    """Hash of the package's Python source (line endings normalized, so Windows and Linux agree)."""
    digest = hashlib.sha256()
    for path in sorted(package_dir.rglob("*.py")):
        relative = path.relative_to(package_dir)
        if relative.parts[0] in _NOT_RESULT_CODE:
            continue
        digest.update(relative.as_posix().encode() + b"\0" + _normalize(path.read_bytes()) + b"\0")
    return digest.hexdigest()[:16]


def git_state() -> tuple[str | None, bool | None]:
    """(commit, has uncommitted changes in src/), or (None, None) outside a git checkout."""
    try:
        commit = _git("rev-parse", "HEAD")
        dirty = bool(_git("status", "--porcelain", "--", str(PACKAGE_DIR)))
    except (OSError, subprocess.SubprocessError):
        return None, None
    return commit[:12], dirty


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=PACKAGE_DIR, capture_output=True, text=True, timeout=10, check=True
    )
    return result.stdout.strip()


def _normalize(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]
