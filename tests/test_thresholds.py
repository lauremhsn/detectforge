"""Gate threshold ablation, recomputed from saved runs (no model)."""

from test_agent_loop import ScriptedClient, tool_call

from detectforge.agent.runner import run_hardening
from detectforge.eval.thresholds import _passes, _Run, threshold_table


def _run(tuning_after, other_checks_pass=True):
    return _Run(
        mode="harden", prompt_version="harden-v7", tuning_after=tuning_after,
        other_checks_pass=other_checks_pass, heldout_mutations=2, heldout_after=1.0,
        new_heldout_false_alarms=0,
    )  # fmt: skip


def test_a_rule_passes_when_it_clears_the_bar_and_every_other_check():
    assert _passes(_run(0.7), 0.6) and not _passes(_run(0.7), 0.8)
    assert not _passes(_run(1.0, other_checks_pass=False), 0.6)  # e.g. it added false alarms
    assert _passes(_run(None), 1.0)  # no mutated tuning attacks: like the gate, nothing to fail


def test_table_from_saved_runs(tmp_path, fixture_events, load_rule_text):
    original = load_rule_text("schtasks_create_literal.yml")
    robust = load_rule_text("schtasks_create_robust.yml")
    for script in (
        [tool_call("submit", rule_yaml=robust, rationale="create verb")],
        [tool_call("validate_rule", rule_yaml=original)] * 25,  # never proposes: left out
    ):
        run_hardening(original, "T1053.005", fixture_events, ScriptedClient(script), "m", out_dir=tmp_path)

    rows = threshold_table(tmp_path, (0.5, 1.0))
    assert [(r.threshold, r.runs, r.passing, r.passing_with_heldout) for r in rows] == [
        (0.5, 1, 1, 1),
        (1.0, 1, 1, 1),
    ]
    assert rows[0].heldout_after_mean == 1.0 and rows[0].passing_with_new_heldout_false_alarms == 0
