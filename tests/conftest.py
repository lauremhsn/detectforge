from pathlib import Path

import pytest

from detectforge.events import load_events
from detectforge.schemas import Event

FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures"


@pytest.fixture(scope="session")
def fixture_events() -> list[Event]:
    return load_events(FIXTURES / "events.jsonl")


@pytest.fixture
def load_rule_text():
    return lambda name: (FIXTURES / "rules" / name).read_text(encoding="utf-8")


def make_rule(detection: str) -> str:
    """Wrap a YAML detection block (indented two spaces) in a minimal in-scope rule."""
    return f"""title: test rule
id: 00000000-0000-4000-8000-000000000000
status: test
logsource:
  category: process_creation
  product: windows
detection:
{detection}
level: low
"""


def make_event(command_line: str = "", image: str = "C:\\Windows\\System32\\cmd.exe", **kw) -> Event:
    fields = {
        "event_id": "e1",
        "image": image,
        "command_line": command_line,
        "parent_image": "C:\\Windows\\explorer.exe",
        "label": "attack",
        "technique": "T1059.003",
        "transform": "none",
        "split": "tune",
    }
    fields.update(kw)
    fields.setdefault("base_id", fields["event_id"])
    return Event(**fields)
