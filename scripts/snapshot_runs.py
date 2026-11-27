"""Refresh the committed snapshot of agent runs that a deployed copy of the UI shows.

Copies every saved run (data/runs/*.json, including review decisions) and the approved rules into
data/snapshot/runs/, and stamps the date. Local notes (decisions-*.txt, walkthroughs) are not copied.
Before copying, it refuses if any run text contains something that looks like an API key.

    df scripts/snapshot_runs.py          # then commit data/snapshot/
"""

import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

SOURCE = Path("data/runs")
TARGET = Path("data/snapshot/runs")
SECRET = re.compile(r"sk-or-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._-]{20,}")


def main() -> int:
    files = sorted(SOURCE.glob("*.json")) + sorted((SOURCE / "approved").glob("*.yml"))
    if not files:
        print(f"no runs in {SOURCE}", file=sys.stderr)
        return 1
    for path in files:
        if SECRET.search(path.read_text(encoding="utf-8", errors="replace")):
            print(f"refusing: {path} looks like it contains a key", file=sys.stderr)
            return 1
    if TARGET.exists():
        shutil.rmtree(TARGET)
    (TARGET / "approved").mkdir(parents=True)
    for path in files:
        shutil.copy2(path, TARGET / path.relative_to(SOURCE))
    stamp = f"{datetime.now(UTC):%Y-%m-%d}"
    (TARGET.parent / "SNAPSHOT.txt").write_text(
        f"{stamp}\n{len(files)} files from {SOURCE}\n", encoding="utf-8"
    )
    print(f"copied {len(files)} files to {TARGET} ({stamp}); commit data/snapshot/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
