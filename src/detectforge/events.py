"""Read and write Event JSONL files."""

from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from detectforge.schemas import Event


class EventFileError(ValueError):
    """An events file has a malformed line."""


def load_events(path: str | Path) -> list[Event]:
    """Load one Event per non-blank line, reporting the line number of the first bad line."""
    events = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                events.append(Event.model_validate_json(line))
            except ValidationError as e:
                raise EventFileError(f"{path}:{lineno}: {e}") from e
    return events


def dump_events(events: Iterable[Event], path: str | Path) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for event in events:
            f.write(event.model_dump_json() + "\n")
