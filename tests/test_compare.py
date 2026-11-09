import json

import pytest

from detectforge.cli import main
from detectforge.harness.compare import compare

from conftest import FIXTURES


@pytest.fixture
def schtasks_events(fixture_events):
    return [e for e in fixture_events if e.technique == "T1053.005"]


def test_hardening_raises_evasion_resistance(schtasks_events, load_rule_text):
    report = compare(
        load_rule_text("schtasks_create_literal.yml"),
        load_rule_text("schtasks_create_robust.yml"),
        schtasks_events,
    )
    assert report.valid
    assert report.mutated_attacks == 4
    assert report.evasion_resistance_before == pytest.approx(0.25)  # only omission survives
    assert report.evasion_resistance_after == pytest.approx(1.0)
    assert report.evasion_resistance_delta == pytest.approx(0.75)
    assert report.newly_detected_event_ids == ["st-002", "st-003", "st-005"]
    assert report.lost_event_ids == []
    assert (report.false_alarms_before, report.false_alarms_after) == (1, 1)
    assert report.new_false_alarm_event_ids == report.removed_false_alarm_event_ids == []

    insertion = report.per_transform["insertion"]
    assert (insertion.attacks, insertion.resistance_before, insertion.resistance_after) == (1, 0.0, 1.0)
    assert report.per_transform["recoding"].resistance_before is None  # no recoding events


def test_regression_is_reported_as_lost(schtasks_events, load_rule_text):
    report = compare(
        load_rule_text("schtasks_create_robust.yml"),
        load_rule_text("schtasks_create_literal.yml"),
        schtasks_events,
    )
    assert report.evasion_resistance_delta == pytest.approx(-0.75)
    assert report.lost_event_ids == ["st-002", "st-003", "st-005"]


def test_invalid_after_rule_makes_report_invalid(schtasks_events, load_rule_text):
    report = compare(load_rule_text("schtasks_create_literal.yml"), "title: [", schtasks_events)
    assert not report.valid and report.before.valid and not report.after.valid
    assert report.evasion_resistance_after is None and report.evasion_resistance_delta is None
    assert report.mutated_attacks == 4 and report.per_transform["insertion"].attacks == 1


def test_cli_compare_filters_split(capsys):
    rules = FIXTURES / "rules"
    code = main(
        [
            "compare",
            str(rules / "schtasks_create_literal.yml"),
            str(rules / "schtasks_create_robust.yml"),
            str(FIXTURES / "events.jsonl"),
            "--split",
            "heldout",
            "--technique",
            "T1053.005",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["mutated_attacks"] == 1  # st-005, reordering
    assert (report["evasion_resistance_before"], report["evasion_resistance_after"]) == (0.0, 1.0)
