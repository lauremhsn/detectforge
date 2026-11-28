"""Stress check: the look-alikes become valid benign events, separate from the main event files."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import stress_check as sc  # noqa: E402

from detectforge.harness import run  # noqa: E402


def test_lookalikes_are_benign_process_events_named_after_their_binary():
    events = sc.lookalike_events(ROOT / "data")
    assert len(events) >= 29 and len({e.event_id for e in events}) == len(events)
    assert all(e.label == "benign" and e.parent_image.endswith("cmd.exe") for e in events)
    reg = next(e for e in events if e.command_line.startswith("reg "))
    assert reg.image.endswith("\\reg.exe") and reg.original_file_name == "reg.exe"


def test_an_over_broad_rule_fires_and_a_precise_one_does_not():
    events = sc.lookalike_events(ROOT / "data")
    base = "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
    broad = (
        base + "  sel:\n    Image|endswith: '\\reg.exe'\n    CommandLine|contains: 'hklm'\n  condition: sel\n"
    )
    precise = (
        base
        + "  sel:\n    Image|endswith: '\\reg.exe'\n    CommandLine|contains: ' save '\n  condition: sel\n"
    )
    assert run(broad, events).matched_event_ids  # reg query/add/delete on HKLM
    assert not run(precise, events).matched_event_ids
