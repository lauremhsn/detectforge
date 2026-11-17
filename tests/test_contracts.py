"""Contracts: the shared formats and functions both halves of the project build on.

The agent, the harness, the dataset tools and the evaluation all exchange the same objects (events,
scorecards, rule records, reports) and call the same functions. If one of them changes shape
silently, the other side breaks later, as wrong numbers in an experiment rather than a failing test.
These tests catch it at once:

- a frozen snapshot of every shared format and public function signature (tests/contracts/);
- docs/interfaces.md must list exactly the fields the code has;
- the committed data files and results must satisfy the contract;
- the CLI's JSON output and exit codes, which scripts depend on.

An intended change: agree it as a team, then refresh the snapshot with
    UPDATE_CONTRACTS=1 uv run pytest tests/test_contracts.py
and commit the snapshot with the change, so the diff shows exactly what changed.
"""

import inspect
import json
import os
import re
from pathlib import Path
from typing import get_args

import pytest

from detectforge import cli
from detectforge.eval.arms import ArmResult, run_community_arm
from detectforge.eval.metrics import RuleResult, score_rule
from detectforge.events import dump_events, load_events
from detectforge.gate import GateResult, check
from detectforge.harness.compare import HardeningReport, compare, evasion_resistance
from detectforge.harness.run import no_rule, run
from detectforge.rules.validate import validate_rule
from detectforge.schemas import (
    TRANSFORMS,
    Event,
    Label,
    RuleRecord,
    RuleSource,
    RuleStatus,
    Scorecard,
    Split,
    Transform,
    ValidationResult,
)

REPO = Path(__file__).resolve().parents[1]
SNAPSHOT = Path(__file__).parent / "contracts" / "interfaces.json"
INTERFACES_DOC = REPO / "docs" / "interfaces.md"
EVAL_DATA = REPO / "data" / "eval"

MODELS = {
    m.__name__: m
    for m in (
        Event,
        Scorecard,
        RuleRecord,
        ValidationResult,
        HardeningReport,
        GateResult,
        RuleResult,
        ArmResult,
    )
}
FUNCTIONS = {
    f"{f.__module__}.{f.__name__}": f
    for f in (
        run,
        no_rule,
        compare,
        evasion_resistance,
        validate_rule,
        load_events,
        dump_events,
        check,
        score_rule,
        run_community_arm,
    )
}


def _current() -> dict:
    return {
        "models": {name: model.model_json_schema() for name, model in MODELS.items()},
        "functions": {name: str(inspect.signature(f)) for name, f in FUNCTIONS.items()},
    }


# ---- frozen snapshot --------------------------------------------------------------------------


def test_shared_formats_and_signatures_match_the_agreed_snapshot():
    current = _current()
    if os.environ.get("UPDATE_CONTRACTS") == "1":
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.skip("contract snapshot rewritten; review and commit tests/contracts/interfaces.json")
    agreed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    changed = [
        f"{kind}.{name}"
        for kind in ("models", "functions")
        for name in sorted(set(agreed[kind]) | set(current[kind]))
        if agreed[kind].get(name) != current[kind].get(name)
    ]
    assert not changed, (
        f"shared interface changed: {', '.join(changed)}. If intended, agree it as a team, then run "
        "UPDATE_CONTRACTS=1 uv run pytest tests/test_contracts.py and commit the snapshot."
    )


def test_the_snapshot_pins_the_week_one_event_and_scorecard_fields():
    """A readable statement of the frozen interface, independent of the snapshot file."""
    assert list(Event.model_fields) == [
        "event_id", "image", "command_line", "parent_image", "original_file_name",
        "parent_command_line", "label", "technique", "transform", "base_id", "split", "verified",
    ]  # fmt: skip
    assert list(Scorecard.model_fields) == [
        "valid", "error", "hits", "misses", "false_alarms", "matched_event_ids", "per_transform",
    ]  # fmt: skip
    assert list(RuleRecord.model_fields) == [
        "rule_yaml",
        "source",
        "technique",
        "trace_id",
        "version",
        "status",
    ]
    assert get_args(Transform) == TRANSFORMS == (
        "none", "insertion", "substitution", "omission", "reordering", "recoding",
    )  # fmt: skip
    assert get_args(Label) == ("attack", "benign") and get_args(Split) == ("tune", "heldout")
    assert get_args(RuleSource) == ("community", "adapted", "written")
    assert get_args(RuleStatus) == ("proposed", "approved", "rejected")


# ---- docs/interfaces.md says what the code does -----------------------------------------------


def _table_fields(section: str) -> list[str]:
    """First-column `names` of the markdown table under a '## section' heading."""
    text = INTERFACES_DOC.read_text(encoding="utf-8")
    body = text.split(f"## {section}\n", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| `([a-z_]+)` \|", body, flags=re.MULTILINE)


def test_the_interfaces_doc_lists_exactly_the_fields_in_the_code():
    assert _table_fields("Event") == list(Event.model_fields)
    assert _table_fields("Scorecard") == list(Scorecard.model_fields)
    record = INTERFACES_DOC.read_text(encoding="utf-8").split("## Rule record\n", 1)[1].split("\n## ", 1)[0]
    assert re.findall(r"`([a-z_]+)` \(|`([a-z_]+)`,", record)  # sanity: the section has field names
    for field in RuleRecord.model_fields:
        assert f"`{field}`" in record, f"docs/interfaces.md 'Rule record' doesn't mention {field}"


def test_the_interfaces_doc_lists_the_allowed_values():
    text = INTERFACES_DOC.read_text(encoding="utf-8")
    assert " \\| ".join(f"`{t}`" for t in TRANSFORMS) in text
    for values in (get_args(RuleSource), get_args(RuleStatus)):
        assert "|".join(f"`{v}`" for v in values) in text


# ---- committed data satisfies the contract ----------------------------------------------------


def _committed_events() -> dict[str, list[Event]]:
    return {p.name: load_events(p) for p in sorted(EVAL_DATA.glob("*.jsonl"))}


@pytest.mark.skipif(not any(EVAL_DATA.glob("*.jsonl")), reason="no evaluation data in this checkout")
def test_committed_event_files_are_one_consistent_dataset():
    files = _committed_events()
    every = [e for events in files.values() for e in events]
    ids = [e.event_id for e in every]
    assert len(ids) == len(set(ids)), "event_id must be unique across all evaluation files"

    by_id = {e.event_id: e for e in every}
    for e in every:
        base = by_id.get(e.base_id)
        assert base is not None, f"{e.event_id}: base_id {e.base_id} is in no evaluation file"
        assert base.transform == "none", f"{e.event_id}: its base {e.base_id} is itself a mutation"
        assert (base.label, base.technique) == (e.label, e.technique), (
            f"{e.event_id}: a variant must keep its base event's label and technique"
        )


@pytest.mark.skipif(not (EVAL_DATA / "results").exists(), reason="no evaluation results in this checkout")
def test_saved_evaluation_results_still_load():
    for path in sorted((EVAL_DATA / "results").glob("arm*.json")):
        ArmResult.model_validate_json(path.read_text(encoding="utf-8"))


def test_events_round_trip_through_jsonl_unchanged(fixture_events, tmp_path):
    path = tmp_path / "events.jsonl"
    dump_events(fixture_events, path)
    assert load_events(path) == fixture_events
    assert all(
        json.loads(line).keys() <= set(Event.model_fields) for line in path.read_text("utf-8").splitlines()
    )


# ---- harness API ------------------------------------------------------------------------------


def test_the_harness_scores_every_event_it_is_given(fixture_events, load_rule_text):
    """It does not filter by technique or split: callers choose the events."""
    card = run(load_rule_text("schtasks_create_robust.yml"), fixture_events)
    attacks = [e for e in fixture_events if e.label == "attack"]
    assert card.hits + card.misses == len(attacks)
    assert sum(b.attacks for b in card.per_transform.values()) == len(attacks)
    assert sum(b.benign for b in card.per_transform.values()) == len(fixture_events) - len(attacks)
    order = [e.event_id for e in fixture_events]
    assert card.matched_event_ids == sorted(card.matched_event_ids, key=order.index)  # input order
    assert Scorecard.model_validate_json(card.model_dump_json()) == card


def test_compare_is_exactly_two_independent_harness_runs(fixture_events, load_rule_text):
    before, after = (
        load_rule_text("schtasks_create_literal.yml"),
        load_rule_text("schtasks_create_robust.yml"),
    )
    report = compare(before, after, fixture_events)
    assert report.before == run(before, fixture_events) and report.after == run(after, fixture_events)
    assert report.evasion_resistance_before == evasion_resistance(report.before)
    assert report.evasion_resistance_after == evasion_resistance(report.after)
    assert compare(None, after, fixture_events).before == no_rule(fixture_events)


# ---- command line: scripts read its JSON and exit codes ---------------------------------------


@pytest.fixture
def files(tmp_path, fixture_events, load_rule_text):
    events = tmp_path / "events.jsonl"
    dump_events(fixture_events, events)
    rules = {}
    for name in ("schtasks_create_literal.yml", "schtasks_create_robust.yml"):
        rules[name] = tmp_path / name
        rules[name].write_text(load_rule_text(name), encoding="utf-8")
    broken = tmp_path / "broken.yml"
    broken.write_text("title: [unclosed", encoding="utf-8")
    return events, rules["schtasks_create_literal.yml"], rules["schtasks_create_robust.yml"], broken


def test_cli_harness_prints_a_scorecard_and_exits_1_on_an_invalid_rule(files, fixture_events, capsys):
    events, literal, _, broken = files
    assert cli.main(["harness", str(literal), str(events)]) == 0
    printed = Scorecard.model_validate_json(capsys.readouterr().out)
    assert printed == run(literal.read_text(encoding="utf-8"), fixture_events)

    assert cli.main(["harness", str(broken), str(events)]) == 1
    printed = Scorecard.model_validate_json(capsys.readouterr().out)
    assert not printed.valid and printed.error


def test_cli_compare_prints_a_report_for_the_requested_slice(files, fixture_events, capsys):
    events, literal, robust, _ = files
    assert cli.main(["compare", str(literal), str(robust), str(events), "--split", "heldout"]) == 0
    report = HardeningReport.model_validate_json(capsys.readouterr().out)
    heldout = [e for e in fixture_events if e.split == "heldout"]
    assert report == compare(literal.read_text("utf-8"), robust.read_text("utf-8"), heldout)
