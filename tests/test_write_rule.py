"""Write-new-rule fallback: who decides the path, the writing loop, hidden same-technique rules, arm 3."""

import json
from datetime import UTC, datetime

import pytest
from test_agent_loop import ScriptedClient, text, tool_call
from test_batch import reference, setup  # noqa: F401  (setup is a pytest fixture)

from detectforge.agent.batch import harden_selection
from detectforge.agent.loop import SYSTEM_PROMPT, WRITE_PROMPT_VERSION, WRITE_SYSTEM_PROMPT, write_rule
from detectforge.agent.runner import cover, find_usable_rule, run_writing
from detectforge.config import Settings
from detectforge.harness.compare import compare
from detectforge.llm import LLMError
from detectforge.reference.index import ReferenceIndex
from detectforge.rules.stamp import stamp_written_rule

TECHNIQUE = "T1053.005"

# The behavior-based fixture rule plus an exclusion for the vendor updater (a benign tuning event), keyed on
# its installer's path under Program Files (costly for an attacker), not on command-line text (free);
# a new rule has no original to compare with, so it must raise no false alarm at all.
WRITTEN = """\
title: Scheduled Task Created With Schtasks
id: 2f0b1c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d
status: experimental
description: A scheduled task is created with schtasks.
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\\schtasks.exe'
    - OriginalFileName: 'schtasks.exe'
  selection_cli:
    CommandLine|contains: 'create'
  filter_vendor:
    ParentImage|startswith: 'C:\\Program Files\\ExampleVendor\\'
  condition: all of selection_* and not filter_vendor
falsepositives:
  - Software installers that register update tasks
level: medium
"""


@pytest.fixture
def settings():
    return Settings(_env_file=None, max_iterations=5, max_model_calls=10)


@pytest.fixture
def events(fixture_events):
    return [e for e in fixture_events if e.technique == TECHNIQUE or e.label == "benign"]


@pytest.fixture
def tuning(events):
    return [e for e in events if e.split == "tune"]


def stamped(rule_yaml, run):
    """What a written rule looks like after code sets its metadata (rules/stamp.py)."""
    return stamp_written_rule(rule_yaml, run.trace_id, datetime.now(UTC).date())


def test_no_rule_is_the_before_of_a_written_rule(events):
    report = compare(None, WRITTEN, events)
    assert report.valid and report.evasion_resistance_before == 0.0
    assert report.false_alarms_before == 0 and report.before.hits == 0
    assert set(report.newly_detected_event_ids) == {e.event_id for e in events if e.label == "attack"}


def test_writing_happy_path(tuning, settings):
    client = ScriptedClient(
        [
            tool_call("inspect_schema"),
            tool_call("run_tuning_set", rule_yaml=WRITTEN),
            tool_call("submit", rule_yaml=WRITTEN, rationale="schtasks plus the create verb"),
        ]
    )
    run = write_rule(TECHNIQUE, tuning, client, "fake", settings=settings)

    assert (
        run.status == "passed"
        and run.final_source == "accepted"
        and run.final_rule_yaml == stamped(WRITTEN, run)
    )
    assert run.mode == "write" and run.prompt_version == WRITE_PROMPT_VERSION
    assert run.original_rule_yaml == "" and run.record.source == "written"
    assert run.tuning_evasion_resistance_before == 0.0 and run.tuning_evasion_resistance_after == 1.0
    # The gate's "new rule" checks: no false alarm at all, nothing compared with an original.
    checks = {c.name for c in run.gate.checks}
    assert "false_alarms" in checks and "no_lost_attacks" not in checks
    system, task = client.requests[0][0]["content"], client.requests[0][1]["content"]
    assert system == WRITE_SYSTEM_PROMPT and "Write a new Sigma rule for ATT&CK technique T1053.005" in task


def test_both_prompts_share_the_lessons_from_real_runs():
    for lesson in ("|cased", "two single quotes", "write each regex escape once", "only once per"):
        assert lesson in SYSTEM_PROMPT and lesson in WRITE_SYSTEM_PROMPT
    assert "WRITE a new Sigma rule" in WRITE_SYSTEM_PROMPT and "harden an EXISTING" in SYSTEM_PROMPT


def test_writing_hides_every_rule_of_the_technique_family(tuning, settings, load_rule_text):
    literal = load_rule_text("schtasks_create_literal.yml")
    index = ReferenceIndex(
        [
            reference("same", literal, "T1053.005"),
            reference("sibling", literal, "T1053.002"),
            reference("other", literal, "T1105"),
        ]
    )
    client = ScriptedClient(
        [
            tool_call("search_reference_rules", technique=TECHNIQUE),
            tool_call("search_reference_rules", query="same sibling other", limit=10),  # their titles
            LLMError("stop"),
        ]
    )
    write_rule(TECHNIQUE, tuning, client, "fake", index=index, settings=settings)
    by_technique = json.loads(client.requests[1][-1]["content"])
    by_query = json.loads(client.requests[2][-1]["content"])
    assert by_technique["output"] == []
    assert [r["id"] for r in by_query["output"]] == ["other"]


def test_writing_that_never_produces_a_rule_proposes_nothing(tuning, settings):
    client = ScriptedClient([text("I would need more context."), text("Still thinking.")])
    run = write_rule(TECHNIQUE, tuning, client, "fake", settings=settings)
    assert run.status == "needs_human_review" and run.final_source == "none"
    assert run.final_rule_yaml == "" and run.tuning_evasion_resistance_after is None
    assert not run.gate.passed and "never proposed a rule" in run.gate.checks[0].detail
    assert any("without submitting" in r for r in run.reasons)


def test_a_rule_the_gate_rejected_is_still_the_best_attempt(tuning, settings):
    """Regression: a rehearsal said "no valid rule" when the agent only submitted (never tested) rules."""
    noisy = WRITTEN.replace(
        "  filter_vendor:\n    ParentImage|startswith: 'C:\\Program Files\\ExampleVendor\\'\n", ""
    ).replace("  condition: all of selection_* and not filter_vendor", "  condition: all of selection_*")
    assert "filter_vendor" not in noisy
    submit = tool_call("submit", rule_yaml=noisy, rationale="flags the vendor updater too")
    run = write_rule(TECHNIQUE, tuning, ScriptedClient([submit] * 3), "fake", settings=settings)
    assert any("rejected every submission" in r for r in run.reasons)
    assert run.final_source == "best_attempt" and run.final_rule_yaml == stamped(noisy, run)
    assert any(c.name == "false_alarms" and not c.passed for c in run.gate.checks)  # why it was rejected


def test_writing_keeps_its_best_valid_version_when_the_model_fails(tuning, settings):
    client = ScriptedClient([tool_call("run_tuning_set", rule_yaml=WRITTEN), LLMError("HTTP 429")])
    run = write_rule(TECHNIQUE, tuning, client, "fake", settings=settings)
    assert run.final_source == "best_attempt" and run.final_rule_yaml == stamped(WRITTEN, run)
    assert run.status == "needs_human_review" and any("LLM unavailable" in r for r in run.reasons)


def test_the_path_is_chosen_by_code_not_the_model(events, load_rule_text, tmp_path):
    literal = load_rule_text("schtasks_create_literal.yml")
    unusable = reference("cannot-fire", literal, TECHNIQUE).model_copy(update={"can_fire": False})
    related = reference("parent-technique", literal, "T1053")  # another behavior: doesn't count

    with_rule = ReferenceIndex([unusable, related, reference("usable", literal, TECHNIQUE)])
    assert find_usable_rule(with_rule, TECHNIQUE).id == "usable"
    submit = tool_call("submit", rule_yaml=WRITTEN, rationale="behavior")
    outcome = cover(TECHNIQUE, events, ScriptedClient([submit]), "fake", with_rule, tmp_path)
    assert outcome.run.mode == "harden" and outcome.run.original_rule_yaml == literal

    without = ReferenceIndex([unusable, related])
    assert find_usable_rule(without, TECHNIQUE) is None and find_usable_rule(None, TECHNIQUE) is None
    outcome = cover(TECHNIQUE, events, ScriptedClient([submit]), "fake", without, tmp_path)
    assert outcome.run.mode == "write" and outcome.run.status == "passed"


def test_written_runs_are_saved_and_scored_on_held_out_without_the_agent_seeing_it(events, tmp_path):
    heldout = [e for e in events if e.split == "heldout"]
    client = ScriptedClient([tool_call("submit", rule_yaml=WRITTEN, rationale="behavior")])
    outcome = run_writing(TECHNIQUE, events, client, "fake", out_dir=tmp_path)

    sent = json.dumps(client.requests)
    assert all(e.event_id not in sent and e.command_line not in sent for e in heldout)
    assert outcome.heldout_evaluation.evasion_resistance_before == 0.0  # no rule before
    assert outcome.heldout_evaluation.evasion_resistance_after == 1.0  # reordering, unseen in tuning
    assert outcome.provenance.prompt_version == WRITE_PROMPT_VERSION
    saved = json.loads((tmp_path / f"{outcome.run.trace_id}.json").read_text(encoding="utf-8"))
    assert saved["run"]["mode"] == "write" and saved["run"]["record"]["source"] == "written"


def test_written_arm_batch_runs_every_rule_and_never_reuses_hardening_runs(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, _ = setup
    submit = tool_call("submit", rule_yaml=WRITTEN, rationale="behavior")
    harden_selection(selection[:2], fixture_events, index, ScriptedClient([submit]), "fake", tmp_path)

    plan = harden_selection(
        selection, fixture_events, index, None, "fake", tmp_path, dry_run=True, mode="write"
    )
    # The strong rule is skipped when hardening (nothing to improve) but written for like any other.
    assert [(i.rule_id, i.action) for i in plan] == [
        ("weak-schtasks", "planned"),
        ("strong-schtasks", "planned"),
        ("missing", "error"),
    ]
    client = ScriptedClient([submit, submit])
    items = harden_selection(selection[:2], fixture_events, index, client, "fake", tmp_path, mode="write")
    assert [i.action for i in items] == ["written", "written"] and len(client.requests) == 2
    assert items[0].tuning_before == 0.0 and items[0].status == "passed"
    again = harden_selection(
        selection[:2], fixture_events, index, ScriptedClient([]), "fake", tmp_path, mode="write"
    )
    assert [i.action for i in again] == ["reused", "reused"]


def test_writing_has_its_own_model_call_budget(tuning):
    """Writing from scratch takes more steps than revising, so it gets a separate budget."""
    settings = Settings(_env_file=None, max_model_calls=10, write_max_model_calls=2)
    assert settings.model_call_budget("write") == 2 and settings.model_call_budget("harden") == 10
    client = ScriptedClient([tool_call("inspect_schema")] * 5)
    run = write_rule(TECHNIQUE, tuning, client, "fake", settings=settings)
    assert len(run.model_calls) == 2
    assert any("model call budget exhausted (2 calls)" in r for r in run.reasons)


def test_write_v2_forbids_look_alike_characters_and_asks_to_submit_early():
    """Regression: the first real write run copied ᵃᵈᵈ and ﹣ from the test attacks and never submitted."""
    assert WRITE_PROMPT_VERSION == "write-v2"
    assert "Never list those characters" in WRITE_SYSTEM_PROMPT and "|windash" in WRITE_SYSTEM_PROMPT
    assert "Submit early" in WRITE_SYSTEM_PROMPT
    assert "Never list those characters" not in SYSTEM_PROMPT  # hardening prompt unchanged (v7)


def test_a_rule_with_no_tuning_variations_is_written_zero_shot_but_not_hardened(
    setup,  # noqa: F811  (the pytest fixture imported from test_batch)
    fixture_events,
    tmp_path,
):
    """With no tuning variations there is nothing to harden against, but a rule can still be written from
    the base attacks: that's the zero-shot subset of the written arm, reported apart by the export."""
    from detectforge.eval.export import export_runs

    index, selection, _ = setup
    no_variations = [e for e in fixture_events if not (e.split == "tune" and e.transform != "none")]
    hardening = harden_selection(selection[:1], no_variations, index, None, "fake", tmp_path, dry_run=True)
    assert hardening[0].action == "skipped" and "no mutated tuning attacks" in hardening[0].note

    client = ScriptedClient([tool_call("submit", rule_yaml=WRITTEN, rationale="behavior")])
    items = harden_selection(selection[:1], no_variations, index, client, "fake", tmp_path, mode="write")
    assert items[0].action == "written" and items[0].tuning_before is None

    export_runs(tmp_path, tmp_path / "out")
    (row,) = [r for r in (tmp_path / "out" / "runs.csv").read_text(encoding="utf-8").splitlines()[1:]]
    assert ",write,True," in row  # mode, zero_shot
    summary = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    (group,) = summary
    assert group["subsets"]["zero_shot"]["runs"] == 1 and group["subsets"]["with_variations"] is None
