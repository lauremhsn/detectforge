"""Agent-level evaluation metrics, computed offline from the saved runs (no model calls).

The harness and the gate score the *rule*. This script scores the *agent*: what it did on the way to
the rule, at the levels the course's evaluation chapter asks for (step, trajectory, end-to-end) and
across its metric families (task success, output quality, tool use, planning, reliability,
efficiency, safety). Everything is read from what each run recorded: its tool calls, its full
transcript (only what the agent saw), its gate results and its provenance.

Lives outside the package on purpose: the package's code fingerprint is part of every run's setup
key, and a reporting script must not change it.

    df scripts/agent_metrics.py --split test                 # print the tables
    df scripts/agent_metrics.py --split test --json out.json # and save every number
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import yaml

from detectforge.eval.export import zero_shot
from detectforge.review import list_runs, load_run

CURRENT_PROMPTS = {"harden-v7", "write-v2"}
# The current tuning / held-out split (substitution + reordering tuned; omission, insertion, recoding
# held out) dates from this merge. Older runs tuned on omission, which was a tuning type then, so they
# would show up as "leaks" against today's split; they belong to an earlier dataset.
SPLIT_SINCE = datetime(2026, 11, 21, 15, 13, 27, tzinfo=UTC)
ALLOWED_TOOLS = {"search_reference_rules", "inspect_schema", "validate_rule", "run_tuning_set", "submit"}
# Tools that re-score a rule: calling one again on the exact same rule text learns nothing new.
SCORING_TOOLS = {"validate_rule", "run_tuning_set"}

# What a rationale claims about the agent's own tuning results (checked against what it measured).
CLAIMS_ALL_CAUGHT = re.compile(r"\b(all|every) (\d+ )?(attack|variant|variation|mutation)s?\b|\b100 ?%", re.I)
CLAIMS_NO_FALSE_ALARMS = re.compile(r"\b(zero|no|0) (new )?false (alarm|positive)s?\b", re.I)


def load_events(data_dir: Path) -> list[dict]:
    events = []
    for name in ("mutations.jsonl", "benign_events.jsonl"):
        path = data_dir / "eval" / name
        events += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return events


def split_of(technique: str, selection: list[dict]) -> str:
    splits = {r["split"] for r in selection if r["technique"] == technique}
    return "dev" if "dev" in splits else "test"


def strings(value: Any) -> list[str]:
    """Every string inside a JSON value (tool results are JSON text inside the transcript)."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return [value]
        return strings(parsed) if isinstance(parsed, (dict, list)) else [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return []


def trajectory(transcript: list[dict]) -> list[tuple[str, dict, dict | None]]:
    """(tool name, arguments, result) for every tool call, in order."""
    results = {m.get("tool_call_id"): m.get("content") for m in transcript if m.get("role") == "tool"}
    steps = []
    for m in transcript:
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {"_unparsable": fn.get("arguments")}
            try:
                result = json.loads(results.get(tc.get("id")) or "null")
            except ValueError:
                result = None
            steps.append((fn.get("name", "?"), args if isinstance(args, dict) else {}, result))
    return steps


def run_metrics(outcome, heldout_texts: set[str], heldout_ids: set[str]) -> dict[str, Any]:
    run = outcome.run
    steps = trajectory(run.transcript)
    names = [n for n, _, _ in steps]
    submits = [(a, r) for n, a, r in steps if n == "submit"]
    submit_passed = [bool(r and r.get("ok") and (r.get("output") or {}).get("passed")) for _, r in submits]

    # Redundant calls: a scoring tool called again on a rule text it already scored in this run.
    seen: set[tuple[str, str]] = set()
    redundant = 0
    for name, args, _ in steps:
        if name in SCORING_TOOLS:
            key = (name, (args.get("rule_yaml") or "").strip())
            redundant += key in seen
            seen.add(key)

    # Gate checks that failed on any submission (what the gate caught, per check).
    failed_checks = Counter()
    for _, r in submits:
        for check in ((r or {}).get("output") or {}).get("checks", []):
            if check.get("blocking") and not check.get("passed"):
                failed_checks[check["name"]] += 1

    # Groundedness: does the rationale claim more than the agent's own last tuning score shows?
    rationale = run.rationale or ""
    tuning_after, fa_after = run.tuning_evasion_resistance_after, run.tuning_false_alarms_after
    claims = {
        "all_caught": bool(CLAIMS_ALL_CAUGHT.search(rationale)),
        "no_false_alarms": bool(CLAIMS_NO_FALSE_ALARMS.search(rationale)),
    }
    unsupported = []
    if claims["all_caught"] and tuning_after is not None and tuning_after < 1.0:
        unsupported.append("all_caught")
    if claims["no_false_alarms"] and fa_after:
        unsupported.append("no_false_alarms")

    # Leakage: any held-out event id or command line among the values the agent saw. Events reach it
    # as whole field values, so match exactly: a held-out omission variant ("... create notepad") is a
    # substring of the tuning command it was made from ("... create notepad.exe"), which is no leak.
    seen_text = set(strings(run.transcript))
    leaked_ids = sorted(heldout_ids & seen_text)
    leaked_cmds = len(heldout_texts & seen_text)

    outage = bool(run.model_calls) and not run.model_calls[-1].ok
    budget_out = any("budget exhausted" in r for r in run.reasons)
    return {
        "trace_id": run.trace_id,
        "mode": run.mode,
        "subset": "" if run.mode == "harden" else ("zero_shot" if zero_shot(outcome) else "with_variations"),
        "technique": run.technique,
        "setup_key": outcome.provenance.setup_key if outcome.provenance else "",
        "budget": (outcome.provenance.budgets.get("model_calls") if outcome.provenance else None),
        "status": run.status,
        "outage": outage,
        "budget_exhausted": budget_out,
        "submitted": bool(submits),
        "passed": run.status == "passed",
        "heldout_after": outcome.heldout_evaluation.evasion_resistance_after
        if outcome.heldout_evaluation
        else None,
        "heldout_scored": bool(outcome.heldout_evaluation and outcome.heldout_evaluation.mutated_attacks),
        "tool_calls": len(run.tool_calls),
        "tool_calls_ok": sum(c.ok for c in run.tool_calls),
        "tool_errors": Counter(c.tool for c in run.tool_calls if not c.ok),
        "tool_counts": Counter(names),
        "unknown_tools": sorted({n for n in names if n not in ALLOWED_TOOLS}),
        "redundant_calls": redundant,
        "measured_first": bool(names) and names[0] in ("run_tuning_set", "inspect_schema"),
        "submissions": len(submits),
        "rejected_submissions": submit_passed.count(False),
        "recovered": (False in submit_passed) and run.status == "passed",
        "stopped_after_pass": not submit_passed or submit_passed[-1] or run.status != "passed",
        "failed_checks": failed_checks,
        "claims": claims,
        "unsupported_claims": unsupported,
        "leaked_heldout_ids": leaked_ids,
        "leaked_heldout_commands": leaked_cmds,
        "record_status": run.record.status,
        "model_calls": len(run.model_calls),
        "fallback_calls": sum(c.used_fallback for c in run.model_calls),
        "failed_model_calls": sum(not c.ok for c in run.model_calls),
        "tokens": run.prompt_tokens + run.completion_tokens,
        "duration_s": run.duration_s,
        "decision": None,
    }


def rate(part: int, whole: int) -> str:
    return f"{part}/{whole} ({part / whole:.0%})" if whole else "n/a"


def summarise(rows: list[dict]) -> dict[str, Any]:
    ran = [r for r in rows if not r["outage"]]
    n = len(ran)
    tool_calls = sum(r["tool_calls"] for r in ran)
    with_rejection = [r for r in ran if r["rejected_submissions"]]
    claimed = [r for r in ran if r["claims"]["all_caught"] or r["claims"]["no_false_alarms"]]
    approved = [r for r in ran if r["decision"] == "approved"]

    # Repeated runs of one setup (same prompt, model, budgets, code, rule, events): variance and pass@k.
    by_setup: dict[str, list[dict]] = defaultdict(list)
    for r in ran:
        by_setup[r["setup_key"]].append(r)
    repeated = {k: v for k, v in by_setup.items() if len(v) > 1}
    spreads = [
        pstdev([x["heldout_after"] or 0 for x in v])
        for v in repeated.values()
        if all(x["heldout_scored"] for x in v)
    ]
    return {
        "runs": n,
        "outages_excluded": len(rows) - n,
        # Task success (end-to-end)
        "completion_submitted_a_rule": rate(sum(r["submitted"] for r in ran), n),
        "success_passed_gate": rate(sum(r["passed"] for r in ran), n),
        "approved_by_reviewer": rate(len(approved), n),
        "stopped_by_budget": rate(sum(r["budget_exhausted"] for r in ran), n),
        "heldout_after_mean": (
            mean([r["heldout_after"] or 0 for r in ran if r["heldout_scored"]])
            if any(r["heldout_scored"] for r in ran)
            else None
        ),
        # Output quality: groundedness of the agent's own claims
        "rationales_with_claims": rate(len(claimed), n),
        "unsupported_claims": rate(sum(bool(r["unsupported_claims"]) for r in claimed), len(claimed)),
        # Tool use (step level)
        "tool_call_success": rate(sum(r["tool_calls_ok"] for r in ran), tool_calls),
        "tool_errors_by_tool": dict(sum((r["tool_errors"] for r in ran), Counter())),
        "calls_per_tool": {
            k: round(v / n, 1) for k, v in sum((r["tool_counts"] for r in ran), Counter()).items()
        },
        "unknown_tool_calls": sum(len(r["unknown_tools"]) for r in ran),
        "redundant_scoring_calls": rate(sum(r["redundant_calls"] for r in ran), tool_calls),
        # Planning / trajectory
        "measured_before_changing": rate(sum(r["measured_first"] for r in ran), n),
        "runs_with_a_rejected_submission": rate(len(with_rejection), n),
        "recovered_after_rejection": rate(sum(r["recovered"] for r in with_rejection), len(with_rejection)),
        "stopped_right_after_passing": rate(sum(r["stopped_after_pass"] for r in ran), n),
        "gate_rejections_by_check": dict(sum((r["failed_checks"] for r in ran), Counter()).most_common()),
        # Reliability
        "setups_repeated": len(repeated),
        "pass_at_k": rate(sum(any(x["passed"] for x in v) for v in repeated.values()), len(repeated)),
        "pass_all_k": rate(sum(all(x["passed"] for x in v) for v in repeated.values()), len(repeated)),
        "heldout_spread_mean": mean(spreads) if spreads else None,
        "runs_using_fallback_model": rate(sum(r["fallback_calls"] > 0 for r in ran), n),
        "model_outages": rate(len(rows) - n, len(rows)),
        # Efficiency
        "model_calls_mean": mean(r["model_calls"] for r in ran) if ran else None,
        "tokens_mean": mean(r["tokens"] for r in ran) if ran else None,
        "seconds_mean": mean(r["duration_s"] for r in ran) if ran else None,
        "model_calls_per_approved_rule": (
            sum(r["model_calls"] for r in ran) / len(approved) if approved else None
        ),
        # Safety
        "runs_with_heldout_leak": rate(
            sum(bool(r["leaked_heldout_ids"] or r["leaked_heldout_commands"]) for r in ran), n
        ),
        "runs_approved_without_human": rate(sum(r["record_status"] != "proposed" for r in ran), n),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--split", choices=["dev", "test", "all"], default="test")
    p.add_argument("--budget", type=int, help="only runs with this write budget (the ablation used 25)")
    p.add_argument("--runs-dir", type=Path, default=Path("data/runs"))
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    p.add_argument("--json", type=Path, help="also save every number here")
    args = p.parse_args()

    selection = yaml.safe_load((args.data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))[
        "rules"
    ]
    events = load_events(args.data_dir)
    heldout = [e for e in events if e.get("split") == "heldout"]
    heldout_ids = {e["event_id"] for e in heldout}
    heldout_texts = {e["command_line"] for e in heldout} - {
        e["command_line"] for e in events if e.get("split") == "tune"
    }  # a command line that is also in the tuning split was legitimately seen

    rows = []
    for s in list_runs(args.runs_dir):
        if s.prompt_version not in CURRENT_PROMPTS or s.created < SPLIT_SINCE:
            continue
        if args.split != "all" and split_of(s.technique, selection) != args.split:
            continue
        outcome = load_run(args.runs_dir, s.trace_id)
        row = run_metrics(outcome, heldout_texts, heldout_ids)
        if args.budget and row["mode"] == "write" and row["budget"] != args.budget:
            continue
        if not args.budget and row["mode"] == "write" and row["budget"] not in (None, 15):
            continue  # the frozen budget only, unless an ablation budget is asked for
        row["decision"] = s.decision.decision if s.decision else "pending"
        rows.append(row)

    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups["hardened" if r["mode"] == "harden" else "written"].append(r)
        if r["subset"]:
            groups[f"written: {r['subset'].replace('_', ' ')}"].append(r)
    results = {name: summarise(g) for name, g in sorted(groups.items())}

    sys.stdout.reconfigure(encoding="utf-8")
    print(
        f"split: {args.split}; runs with the current prompts ({', '.join(sorted(CURRENT_PROMPTS))}) "
        f"on the current mutation split (since {SPLIT_SINCE:%Y-%m-%d %H:%M} UTC)"
    )
    for name, res in results.items():
        print(f"\n== {name}")
        for key, value in res.items():
            if isinstance(value, float):
                value = f"{value:.2f}" if "mean" not in key or value > 1 else f"{value:.0%}"
            print(f"  {key:34} {value}")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        print(f"\nsaved to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
