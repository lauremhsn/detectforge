"""Human review: listing runs, decisions with history, approved copies, and safe file handling."""

import pytest
from pydantic import ValidationError
from test_agent_loop import ScriptedClient, tool_call

from detectforge.agent.runner import run_hardening
from detectforge.review import decisions, list_runs, load_run, record_decision

TECHNIQUE = "T1053.005"


@pytest.fixture
def runs_dir(tmp_path):
    return tmp_path / "runs"


@pytest.fixture
def make_run(runs_dir, fixture_events, load_rule_text):
    original = load_rule_text("schtasks_create_literal.yml")
    robust = load_rule_text("schtasks_create_robust.yml")

    def _make(passes=True):
        script = (
            [tool_call("submit", rule_yaml=robust, rationale="create verb")]
            if passes
            else [tool_call("validate_rule", rule_yaml=original)] * 25
        )
        return run_hardening(
            original, TECHNIQUE, fixture_events, ScriptedClient(script), "fake", out_dir=runs_dir
        )

    return _make


def test_list_runs_summarises_each_run_newest_first(runs_dir, make_run):
    first, second = make_run(passes=True), make_run(passes=False)
    runs = list_runs(runs_dir)
    assert [r.trace_id for r in runs] == [second.run.trace_id, first.run.trace_id]
    top = runs[1]
    assert (top.technique, top.status, top.decision) == (TECHNIQUE, "passed", None)
    assert (top.tuning_before, top.tuning_after) == (pytest.approx(1 / 3), 1.0)
    assert (top.heldout_before, top.heldout_after) == (0.0, 1.0)
    assert runs[0].status == "needs_human_review"


def test_approval_is_recorded_and_the_rule_is_copied(runs_dir, make_run):
    outcome = make_run()
    record = record_decision(runs_dir, outcome.run.trace_id, "approved", "  analyst  ", "looks good")
    assert record.status == "approved" and record.trace_id == outcome.run.trace_id
    (decision,) = decisions(runs_dir, outcome.run.trace_id)
    assert (decision.decision, decision.reviewer, decision.comment) == ("approved", "analyst", "looks good")
    approved = runs_dir / "approved" / f"{outcome.run.trace_id}.yml"
    assert approved.read_text(encoding="utf-8") == outcome.run.final_rule_yaml
    assert list_runs(runs_dir)[0].decision.decision == "approved"


def test_a_later_rejection_keeps_history_and_withdraws_the_approval(runs_dir, make_run):
    trace_id = make_run().run.trace_id
    record_decision(runs_dir, trace_id, "approved", "analyst")
    record_decision(runs_dir, trace_id, "rejected", "lead", "matches too broadly")
    assert [d.decision for d in decisions(runs_dir, trace_id)] == ["approved", "rejected"]
    assert not (runs_dir / "approved" / f"{trace_id}.yml").exists()


def test_a_decision_needs_a_reviewer_name(runs_dir, make_run):
    trace_id = make_run().run.trace_id
    with pytest.raises(ValidationError):
        record_decision(runs_dir, trace_id, "approved", "   ")
    assert decisions(runs_dir, trace_id) == []


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "ABC", "0" * 31, "g" * 32])
def test_only_well_formed_trace_ids_reach_the_file_system(runs_dir, bad_id):
    with pytest.raises(ValueError, match="invalid trace id"):
        load_run(runs_dir, bad_id)
    with pytest.raises(ValueError, match="invalid trace id"):
        record_decision(runs_dir, bad_id, "approved", "analyst")


def test_unreadable_files_are_skipped_not_fatal(runs_dir, make_run):
    make_run()
    (runs_dir / ("f" * 32 + ".json")).write_text("{not a run", encoding="utf-8")
    (runs_dir / "notes.json").write_text("{}", encoding="utf-8")
    assert len(list_runs(runs_dir)) == 1


def test_no_runs_directory_means_no_runs(tmp_path):
    assert list_runs(tmp_path / "missing") == []
