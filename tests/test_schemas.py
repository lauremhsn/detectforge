import pytest
from pydantic import ValidationError

from detectforge.events import EventFileError, dump_events, load_events
from detectforge.schemas import TRANSFORMS, RuleRecord, Scorecard

from conftest import make_event


def test_transforms_are_the_five_uetz_types_plus_none():
    assert TRANSFORMS == ("none", "insertion", "substitution", "omission", "reordering", "recoding")


@pytest.mark.parametrize(
    "overrides",
    [
        {"label": "malicious"},
        {"transform": "renaming"},
        {"split": "test"},
        {"technique": "1053.005"},
        {"event_id": ""},
        {"transform": "none", "base_id": "other"},
        {"transform": "insertion", "base_id": "e1"},
        {"unexpected_field": 1},
    ],
)
def test_event_rejects_invalid_fields(overrides):
    with pytest.raises(ValidationError):
        make_event(**overrides)


def test_mutated_event_references_base():
    event = make_event(event_id="e2", transform="insertion", base_id="e1")
    assert event.base_id == "e1"


def test_events_roundtrip_jsonl(tmp_path):
    events = [make_event(event_id="a"), make_event(event_id="b", transform="omission", base_id="a")]
    path = tmp_path / "events.jsonl"
    dump_events(events, path)
    assert load_events(path) == events


def test_load_events_reports_bad_line(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(make_event().model_dump_json() + "\n\n{not json}\n", encoding="utf-8")
    with pytest.raises(EventFileError, match=r"events.jsonl:3"):
        load_events(path)


def test_default_scorecard_has_every_transform():
    assert set(Scorecard(valid=False).per_transform) == set(TRANSFORMS)


def test_rule_record_defaults_to_proposed():
    record = RuleRecord(rule_yaml="x", source="adapted", technique="T1105", trace_id="t", version=1)
    assert record.status == "proposed"
    with pytest.raises(ValidationError):
        RuleRecord(rule_yaml="x", source="deployed", technique="T1105", trace_id="t", version=1)
