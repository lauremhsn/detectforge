"""Nightly re-validation: what counts as a logic change, and what the report says."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import revalidate_latest as rv


def test_only_detection_logic_counts_as_a_change():
    a = (
        "title: x\nmodified: 2024-01-01\ndetection:\n  sel:\n"
        "    CommandLine|contains: ' save '\n  condition: sel\n"
    )
    b = a.replace("2024-01-01", "2026-05-05")  # metadata edit: not a change
    c = a.replace(" save ", " export ")
    assert rv._logic(a) == rv._logic(b) and rv._logic(a) != rv._logic(c)


def test_report_names_regressions_and_says_when_nothing_changed():
    quiet = {"removed": [], "changed_logic": [], "worse": [], "better": [], "kept": 27}
    assert "No change" in rv.report("r2", "r1", quiet)
    worse = {**quiet, "worse": [("id", "Reg hive dump", 0.75, 0.5)]}
    assert "went DOWN" in rv.report("r2", "r1", worse) and "75% → 50%" in rv.report("r2", "r1", worse)
