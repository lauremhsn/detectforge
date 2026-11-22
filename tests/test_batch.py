"""Batch hardening over a selection: per-rule scoping, skips that save quota, and stopping early."""

import json

import pytest
from test_agent_loop import ScriptedClient, tool_call

from detectforge.agent.batch import BatchItem, SelectedRule, harden_selection, heldout_summary, load_selection
from detectforge.agent.runner import run_hardening
from detectforge.llm import LLMError
from detectforge.reference.index import ReferenceIndex, ReferenceRule


def reference(rule_id, rule_yaml, technique):
    return ReferenceRule(
        id=rule_id,
        title=rule_id,
        path=f"rules/{rule_id}.yml",
        status="test",
        level="medium",
        description="",
        techniques=[technique],
        falsepositives=[],
        fields=["Image", "CommandLine"],
        unmapped_fields=[],
        evaluable=True,
        can_fire=True,
        detection_text="",
        rule_yaml=rule_yaml,
    )


@pytest.fixture
def setup(load_rule_text):
    literal = load_rule_text("schtasks_create_literal.yml")
    robust = load_rule_text("schtasks_create_robust.yml")
    certutil = load_rule_text("certutil_download_literal.yml")
    index = ReferenceIndex(
        [
            reference("weak-schtasks", literal, "T1053.005"),
            reference("strong-schtasks", robust, "T1053.005"),
            reference("weak-certutil", certutil, "T1105"),
        ]
    )
    selection = [
        SelectedRule(
            id="weak-schtasks", title="weak", technique="T1053.005", split="dev", base_attacks=["st-001"]
        ),
        SelectedRule(
            id="strong-schtasks", title="strong", technique="T1053.005", split="dev", base_attacks=["st-001"]
        ),
        SelectedRule(
            id="weak-certutil", title="certutil", technique="T1105", split="test", base_attacks=["cu-001"]
        ),
        SelectedRule(id="missing", title="gone", technique="T1105", split="dev", base_attacks=["cu-001"]),
    ]
    return index, selection, robust


def test_only_improvable_dev_rules_cost_model_calls(setup, fixture_events, tmp_path):
    index, selection, robust = setup
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="create verb")])
    items = harden_selection(selection, fixture_events, index, client, "fake", tmp_path)

    by_id = {i.rule_id: i for i in items}
    assert set(by_id) == {"weak-schtasks", "strong-schtasks", "missing"}  # the test rule is never touched
    assert by_id["weak-schtasks"].action == "hardened" and by_id["weak-schtasks"].status == "passed"
    assert (by_id["weak-schtasks"].tuning_before, by_id["weak-schtasks"].tuning_after) == (
        pytest.approx(1 / 3),
        1.0,
    )
    assert by_id["strong-schtasks"].action == "skipped" and "already detects" in by_id["strong-schtasks"].note
    assert by_id["missing"].action == "error"
    assert len(client.requests) == 1  # one model call in total


def test_all_flag_and_limit(setup, fixture_events, tmp_path):
    index, selection, robust = setup
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="x")] * 2)
    items = harden_selection(
        selection, fixture_events, index, client, "fake", tmp_path, only_improvable=False, limit=1
    )
    by_id = {i.rule_id: i for i in items}
    assert by_id["weak-schtasks"].action == "hardened"
    assert by_id["strong-schtasks"].note == "batch limit reached"


def test_batch_stops_when_the_model_is_unavailable(setup, fixture_events, tmp_path):
    index, selection, _ = setup
    selection = [selection[0], selection[0].model_copy(update={"id": "weak-schtasks"})]
    client = ScriptedClient([LLMError("HTTP 429")])
    items = harden_selection(selection, fixture_events, index, client, "fake", tmp_path)
    assert len(items) == 1 and items[0].note.startswith("stopped the batch")
    assert "429" in items[0].note


def test_scoping_to_unknown_base_attacks_is_rejected(fixture_events, load_rule_text):
    with pytest.raises(ValueError, match="these base attacks"):
        run_hardening(
            load_rule_text("schtasks_create_robust.yml"),
            "T1053.005",
            fixture_events,
            ScriptedClient([]),
            "fake",
            base_ids={"some-other-base"},
        )


def test_scoping_keeps_benign_events(fixture_events, load_rule_text):
    robust = load_rule_text("schtasks_create_robust.yml")
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="x")])
    run_hardening(
        load_rule_text("schtasks_create_literal.yml"),
        "T1053.005",
        fixture_events,
        client,
        "fake",
        base_ids={"st-001"},
    )
    sent = json.dumps(client.requests)
    assert "2/4 attacks" in sent  # st-001 and its 3 tuning mutations; the literal rule catches 2
    assert "with 1 false alarms" in sent  # the benign vendor task is still in scope


def test_load_selection_reads_the_manifest(tmp_path):
    path = tmp_path / "selection.yml"
    path.write_text(
        "rules:\n- id: abc\n  title: T\n  technique: T1490\n  split: dev\n"
        "  base_attacks: [T1490-b01]\n  level: high\n",
        encoding="utf-8",
    )
    (rule,) = load_selection(path)
    assert (rule.id, rule.split, rule.base_attacks) == ("abc", "dev", ["T1490-b01"])


def test_every_rule_is_checked_against_all_benign_events(fixture_events):
    """A legitimate command is a false alarm for any rule, whatever technique it was collected for."""
    from detectforge.agent.runner import scope_events

    scoped = scope_events(fixture_events, "T1053.005", base_ids={"st-001"})
    benign = {e.event_id for e in scoped if e.label == "benign"}
    assert {"st-101", "cu-101"} <= benign  # certutil benign events (T1105) are in scope too
    attacks = {e.base_id for e in scoped if e.label == "attack"}
    assert attacks == {"st-001"}  # attacks stay limited to this rule's own base attacks


def test_new_held_out_false_alarms_are_flagged_for_the_reviewer(setup, fixture_events, tmp_path):
    """The gate can't see held-out benign events, so the batch summary must name them."""
    from detectforge.schemas import Event

    index, selection, robust = setup
    lookalike = Event(
        event_id="benign-query",
        image=r"C:\Windows\System32\schtasks.exe",
        command_line='schtasks /query /tn "CreateExplorerShellUnelevatedTask"',
        parent_image=r"C:\Windows\explorer.exe",
        label="benign",
        technique="T1053.005",
        transform="none",
        base_id="benign-query",
        split="heldout",
    )
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="create verb")])
    items = harden_selection(selection[:1], [*fixture_events, lookalike], index, client, "fake", tmp_path)
    assert items[0].status == "passed"  # invisible to the gate...
    assert "new held-out false alarms: benign-query" in items[0].note  # ...but not to the reviewer


def test_held_out_mean_leaves_out_rules_without_held_out_mutations(setup, fixture_events, tmp_path):
    index, selection, robust = setup
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="create verb")])
    items = harden_selection(selection, fixture_events, index, client, "fake", tmp_path)
    hardened = next(i for i in items if i.action == "hardened")
    assert hardened.heldout_mutations > 0

    no_heldout = BatchItem(rule_id="x", title="x", technique="T1", action="hardened", tuning_before=0.5)
    invalid = BatchItem(
        rule_id="y", title="y", technique="T2", action="hardened", heldout_before=0.5, heldout_mutations=2
    )  # the hardened rule couldn't be evaluated (after = None): it detects nothing, so it counts as 0
    summary = heldout_summary([*items, no_heldout, invalid])
    assert (summary.runs, summary.runs_with_heldout, summary.rules) == (3, 2, 3)
    assert heldout_summary([no_heldout, no_heldout]).rules == 1  # --repeat: 2 runs of 1 rule
    assert summary.mean_before == pytest.approx((hardened.heldout_before + 0.5) / 2)
    assert summary.mean_after == pytest.approx(hardened.heldout_after / 2)
    assert heldout_summary([no_heldout]).mean_after is None  # n/a, not 0%
