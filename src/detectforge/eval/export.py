"""Export every saved agent run as tables for the report: one row per run, model call and tool call.

The report's operational numbers come from here: cost and time per accepted rule, iterations to pass
the gate, model failures and fallbacks, and the before/after scores, with mean and spread per
configuration (mode, prompt version, model). Reads saved run files only; never calls a model.

Output (a directory):
  runs.csv          one row per run: outcome, scores, budgets used, review decision, provenance
  model_calls.csv   one row per model call: latency, tokens, fallback, error, cut-off
  tool_calls.csv    one row per tool call: tool, latency, error
  summary.json      per configuration: counts, pass and approval rates, mean/stdev/min/max of each metric
"""

import csv
import json
import statistics
from collections import defaultdict
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

import yaml

from detectforge.agent.runner import HardeningOutcome
from detectforge.llm import ModelCallRecord
from detectforge.review import RunSummary, latest_prompt_versions, list_runs, load_run

RUN_COLUMNS = [
    "trace_id", "created", "mode", "zero_shot", "technique", "rule_id", "rule_title", "prompt_version",
    "model", "model_call_budget",
    "status", "final_source", "gate_passed", "failed_checks", "decision", "reviewer",
    "tuning_resistance_before", "tuning_resistance_after", "heldout_resistance_before",
    "heldout_resistance_after", "tuning_false_alarms_before", "tuning_false_alarms_after",
    "heldout_false_alarms_before", "heldout_false_alarms_after", "tuning_runs_used", "model_calls",
    "failed_model_calls", "fallback_calls", "cut_off_answers", "tool_calls", "failed_tool_calls",
    "prompt_tokens", "completion_tokens", "duration_s", "cost_usd", "setup_key", "git_commit",
]  # fmt: skip
MODEL_CALL_COLUMNS = [f.name for f in fields(ModelCallRecord)]
SUMMARY_METRICS = [
    "heldout_resistance_after", "heldout_false_alarms_after", "tuning_runs_used", "model_calls",
    "prompt_tokens", "completion_tokens", "duration_s",
]  # fmt: skip


def cost_usd(model: str, tokens: int) -> float | None:
    """Free OpenRouter models cost nothing; for any other model the price isn't recorded (None)."""
    return 0.0 if model.endswith(":free") or tokens == 0 else None


def zero_shot(outcome: HardeningOutcome) -> bool:
    """A written rule whose agent saw no attack variation at all, only the base attacks.

    Its held-out score is pure zero-shot generalization, so it's reported as its own subset rather than
    pulling down (or up) the written arm's average. "No variations to measure" is a None tuning score.
    """
    run = outcome.run
    return run.mode == "write" and run.tuning_evasion_resistance_before is None


def run_row(outcome: HardeningOutcome, summary: RunSummary) -> dict[str, Any]:
    run, heldout, prov = outcome.run, outcome.heldout_evaluation, outcome.provenance
    meta = _metadata(run.original_rule_yaml or run.final_rule_yaml)
    calls = run.model_calls
    tokens = run.prompt_tokens + run.completion_tokens
    return {
        "trace_id": run.trace_id,
        "created": summary.created.isoformat(timespec="seconds"),
        "mode": run.mode,
        "zero_shot": zero_shot(outcome),
        "technique": run.technique,
        "rule_id": meta.get("id", ""),
        "rule_title": meta.get("title", ""),
        "prompt_version": run.prompt_version,
        "model": run.model,
        "model_call_budget": prov.budgets.get("model_calls") if prov else None,
        "status": run.status,
        "final_source": run.final_source,
        "gate_passed": run.gate.passed,
        "failed_checks": ";".join(c.name for c in run.gate.checks if c.blocking and not c.passed),
        "decision": summary.decision.decision if summary.decision else "pending",
        "reviewer": summary.decision.reviewer if summary.decision else "",
        "tuning_resistance_before": run.tuning_evasion_resistance_before,
        "tuning_resistance_after": run.tuning_evasion_resistance_after,
        "heldout_resistance_before": heldout.evasion_resistance_before if heldout else None,
        "heldout_resistance_after": heldout.evasion_resistance_after if heldout else None,
        "tuning_false_alarms_before": run.tuning_false_alarms_before,
        "tuning_false_alarms_after": run.tuning_false_alarms_after,
        "heldout_false_alarms_before": heldout.false_alarms_before if heldout else None,
        "heldout_false_alarms_after": heldout.false_alarms_after if heldout else None,
        "tuning_runs_used": run.tuning_runs_used,
        "model_calls": len(calls),
        "failed_model_calls": sum(not c.ok for c in calls),
        "fallback_calls": sum(c.used_fallback for c in calls),
        "cut_off_answers": sum(c.finish_reason == "length" for c in calls),
        "tool_calls": len(run.tool_calls),
        "failed_tool_calls": sum(not c.ok for c in run.tool_calls),
        "prompt_tokens": run.prompt_tokens,
        "completion_tokens": run.completion_tokens,
        "duration_s": round(run.duration_s, 1),
        "cost_usd": cost_usd(run.model, tokens),
        "setup_key": prov.setup_key if prov else "",
        "git_commit": (prov.git_commit or "") if prov else "",
    }


def summarise(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per configuration (mode, prompt version, model, model-call budget): counts, rates, spreads.

    The budget is part of the configuration: an ablation run with a larger budget is a different
    setup, and averaging it with the frozen-budget runs would blur both.
    """
    groups: dict[tuple[str, str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        budget = row["model_call_budget"] if row["model_call_budget"] is not None else -1
        groups[(row["mode"], row["prompt_version"], row["model"], budget)].append(row)
    out = []
    for (mode, version, model, budget), group in sorted(groups.items()):
        entry = {
            "mode": mode,
            "prompt_version": version,
            "model": model,
            "model_call_budget": None if budget == -1 else budget,
            **_stats(group),
        }
        if mode == "write":  # written with variations to learn from vs zero-shot, reported apart
            entry["subsets"] = {
                name: _stats(rows) if rows else None
                for name, rows in (
                    ("with_variations", [r for r in group if not r["zero_shot"]]),
                    ("zero_shot", [r for r in group if r["zero_shot"]]),
                )
            }
        out.append(entry)
    return out


def _stats(group: list[dict[str, Any]]) -> dict[str, Any]:
    passed = [r for r in group if r["status"] == "passed"]
    approved = [r for r in group if r["decision"] == "approved"]
    costs = [r["cost_usd"] for r in group]
    return {
        "runs": len(group),
        "techniques": len({r["technique"] for r in group}),
        "passed_gate": len(passed),
        "approved": len(approved),
        "rejected": sum(r["decision"] == "rejected" for r in group),
        "pending": sum(r["decision"] == "pending" for r in group),
        "gate_pass_rate": len(passed) / len(group),
        "runs_with_failed_model_calls": sum(r["failed_model_calls"] > 0 for r in group),
        "runs_with_fallback": sum(r["fallback_calls"] > 0 for r in group),
        # Everything spent in the configuration, divided by what a human accepted.
        "cost_usd_per_approved_rule": (
            sum(costs) / len(approved) if approved and None not in costs else None
        ),
        "model_calls_per_approved_rule": (
            sum(r["model_calls"] for r in group) / len(approved) if approved else None
        ),
        "metrics": {m: _spread([r[m] for r in group]) for m in SUMMARY_METRICS},
        "metrics_passed_runs": {m: _spread([r[m] for r in passed]) for m in SUMMARY_METRICS},
    }


def export_runs(runs_dir: Path, out_dir: Path, current_prompts_only: bool = False) -> dict[str, int]:
    """Write the four files; returns how many rows each table got."""
    summaries = list_runs(runs_dir)
    if current_prompts_only:
        current = latest_prompt_versions(summaries)
        summaries = [s for s in summaries if s.prompt_version in current]
    rows, model_rows, tool_rows = [], [], []
    for summary in reversed(summaries):  # oldest first reads naturally in a spreadsheet
        outcome = load_run(runs_dir, summary.trace_id)
        rows.append(run_row(outcome, summary))
        for i, c in enumerate(outcome.run.model_calls, 1):
            model_rows.append({"trace_id": summary.trace_id, "call": i, **asdict(c)})
        for i, t in enumerate(outcome.run.tool_calls, 1):
            tool_rows.append({"trace_id": summary.trace_id, "call": i, **t.model_dump()})

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(out_dir / "runs.csv", RUN_COLUMNS, rows)
    _write_csv(out_dir / "model_calls.csv", ["trace_id", "call", *MODEL_CALL_COLUMNS], model_rows)
    _write_csv(
        out_dir / "tool_calls.csv", ["trace_id", "call", "tool", "ok", "latency_ms", "error"], tool_rows
    )
    (out_dir / "summary.json").write_text(json.dumps(summarise(rows), indent=2), encoding="utf-8")
    return {"runs": len(rows), "model_calls": len(model_rows), "tool_calls": len(tool_rows)}


def _spread(values: list[Any]) -> dict[str, float | int | None]:
    nums = [v for v in values if isinstance(v, int | float) and not isinstance(v, bool)]
    if not nums:
        return {"n": 0, "mean": None, "stdev": None, "min": None, "max": None}
    return {
        "n": len(nums),
        "mean": statistics.fmean(nums),
        "stdev": statistics.stdev(nums) if len(nums) > 1 else 0.0,
        "min": min(nums),
        "max": max(nums),
    }


def _metadata(rule_yaml: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(rule_yaml) if rule_yaml else None
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
