"""Export of saved runs: one row per run / model call / tool call, and a per-configuration summary."""

import csv
import json

from test_agent_loop import ScriptedClient, tool_call

from detectforge.agent.runner import run_hardening
from detectforge.cli import main
from detectforge.eval.export import RUN_COLUMNS, cost_usd, export_runs
from detectforge.review import record_decision

TECHNIQUE = "T1053.005"


def _runs(tmp_path, fixture_events, load_rule_text):
    runs_dir = tmp_path / "runs"
    original = load_rule_text("schtasks_create_literal.yml")
    robust = load_rule_text("schtasks_create_robust.yml")
    passed = run_hardening(
        original, TECHNIQUE, fixture_events,
        ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="create verb")]),
        "m:free", out_dir=runs_dir,
    )  # fmt: skip
    failed = run_hardening(
        original, TECHNIQUE, fixture_events,
        ScriptedClient([tool_call("validate_rule", rule_yaml=original)] * 25), "m:free", out_dir=runs_dir,
    )  # fmt: skip
    record_decision(runs_dir, passed.run.trace_id, "approved", "analyst")
    return runs_dir, passed, failed


def _read(path):
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_every_run_and_call_is_exported(tmp_path, fixture_events, load_rule_text):
    runs_dir, passed, failed = _runs(tmp_path, fixture_events, load_rule_text)
    counts = export_runs(runs_dir, tmp_path / "out")

    rows = {r["trace_id"]: r for r in _read(tmp_path / "out" / "runs.csv")}
    assert counts["runs"] == 2 and set(rows) == {passed.run.trace_id, failed.run.trace_id}
    assert list(_read(tmp_path / "out" / "runs.csv")[0]) == RUN_COLUMNS
    good = rows[passed.run.trace_id]
    assert (good["status"], good["decision"], good["reviewer"]) == ("passed", "approved", "analyst")
    assert (good["heldout_resistance_before"], good["heldout_resistance_after"]) == ("0.0", "1.0")
    assert good["rule_id"] and good["cost_usd"] == "0.0"
    assert rows[failed.run.trace_id]["status"] == "needs_human_review"

    calls = _read(tmp_path / "out" / "model_calls.csv")
    assert len(calls) == counts["model_calls"] == len(passed.run.model_calls) + len(failed.run.model_calls)
    assert {"latency_ms", "prompt_tokens", "used_fallback", "finish_reason"} <= set(calls[0])
    assert len(_read(tmp_path / "out" / "tool_calls.csv")) == counts["tool_calls"]


def test_summary_reports_rates_and_spread_per_configuration(tmp_path, fixture_events, load_rule_text):
    runs_dir, *_ = _runs(tmp_path, fixture_events, load_rule_text)
    export_runs(runs_dir, tmp_path / "out")
    (group,) = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    assert (group["mode"], group["runs"], group["passed_gate"], group["approved"]) == ("harden", 2, 1, 1)
    assert group["gate_pass_rate"] == 0.5 and group["cost_usd_per_approved_rule"] == 0.0
    calls = group["metrics"]["model_calls"]
    assert calls["n"] == 2 and calls["min"] <= calls["mean"] <= calls["max"] and calls["stdev"] >= 0
    assert group["metrics_passed_runs"]["heldout_resistance_after"]["mean"] == 1.0


def test_a_different_model_call_budget_is_a_different_configuration():
    from detectforge.eval.export import SUMMARY_METRICS, summarise

    def row(budget: int, passed: bool) -> dict:
        return {
            "mode": "write", "prompt_version": "write-v2", "model": "m:free", "model_call_budget": budget,
            "zero_shot": False, "technique": "T1", "status": "passed" if passed else "needs_human_review",
            "decision": "pending", "cost_usd": 0.0, "failed_model_calls": 0, "fallback_calls": 0,
            **{m: 1.0 for m in SUMMARY_METRICS},
        }  # fmt: skip

    groups = summarise([row(15, False), row(15, True), row(25, True), row(25, True)])
    by_budget = {g["model_call_budget"]: g for g in groups}
    assert set(by_budget) == {15, 25}  # the ablation is never averaged into the frozen budget
    assert (by_budget[15]["gate_pass_rate"], by_budget[25]["gate_pass_rate"]) == (0.5, 1.0)


def test_unknown_prices_are_not_reported_as_free():
    assert cost_usd("vendor/model:free", 500) == 0.0
    assert cost_usd("vendor/paid-model", 500) is None


def test_export_command(tmp_path, fixture_events, load_rule_text, monkeypatch, capsys):
    from detectforge.config import get_settings

    runs_dir, *_ = _runs(tmp_path, fixture_events, load_rule_text)
    monkeypatch.setenv("DETECTFORGE_DATA_DIR", str(runs_dir.parent))
    get_settings.cache_clear()
    try:
        assert main(["export", "--out", str(tmp_path / "cli")]) == 0
    finally:
        get_settings.cache_clear()
    assert "2 runs" in capsys.readouterr().out and (tmp_path / "cli" / "summary.json").exists()
