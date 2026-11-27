"""Which saved runs the UI shows: this machine's runs, or the committed snapshot.

Agent runs live in data/runs/, which is not in git (it grows with every run). A deployed copy of the
app (Streamlit Community Cloud) therefore has none, and would show empty review queues and "n/a"
results. data/snapshot/runs/ is a committed copy of the evaluation's runs and decisions (refreshed
with scripts/snapshot_runs.py); the UI reads it only when this machine has no runs of its own, and
says so on every page. New agent runs are always saved to data/runs/, never into the snapshot.
"""

from pathlib import Path

from detectforge.config import get_settings


def _has_runs(path: Path) -> bool:
    return path.is_dir() and any(path.glob("*.json"))


def snapshot_dir() -> Path:
    return get_settings().data_dir / "snapshot" / "runs"


def runs_dir() -> Path:
    own = get_settings().runs_dir
    if _has_runs(own) or not _has_runs(snapshot_dir()):
        return own
    return snapshot_dir()


def using_snapshot() -> bool:
    return runs_dir() == snapshot_dir()


def snapshot_date() -> str:
    stamp = snapshot_dir().parent / "SNAPSHOT.txt"
    try:
        return stamp.read_text(encoding="utf-8").strip().splitlines()[0]
    except (OSError, IndexError):
        return "an earlier date"
