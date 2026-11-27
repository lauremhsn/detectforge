"""Lab: the research side. How the system is evaluated, what the agent costs, and where it fails.

Read from the committed evaluation results and the saved runs (every model and tool call is recorded
in them), so it works without the tracing backend. Free models cost nothing in money; the budget that
matters is the provider's daily request limit, shown next to today's usage.
"""

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st
from pydantic import ValidationError

from detectforge.config import get_settings
from detectforge.eval.arms import ArmResult
from detectforge.review import calls_today, list_runs, load_run
from detectforge.ui.bench import bench_settings
from detectforge.ui.components import md, pct, table
from detectforge.ui.navigation import header
from detectforge.ui.results import headline


def operations_page(runs_dir: Path, data_dir: Path | None = None) -> None:
    header(
        "operations",
        "The research side, kept apart from the product: how DetectForge itself is evaluated, what the "
        "agent costs, where it fails, and which events rules are tested on.",
    )
    summaries = list_runs(runs_dir)
    runs = [load_run(runs_dir, s.trace_id).run for s in summaries]
    evaluation, overview, versions, failures, all_runs, bench = st.tabs(
        ["Evaluation", "Agent activity", "Prompt versions", "Failures", "All runs", "Test bench"]
    )
    with bench:
        st.caption(
            "Which events rules are replayed on, everywhere in the app. Product users never need to change "
            "this: a rule is tested on every attack and look-alike of its own technique."
        )
        bench_settings()
    with evaluation:
        _evaluation(data_dir or get_settings().data_dir, runs_dir)
    if not runs:
        overview.info("No agent runs yet.")
        return
    with overview:
        _overview(runs_dir, runs)
    with versions:
        _versions(runs)
    with failures:
        _failures(runs)
    with all_runs:
        table(
            [
                {
                    "when": s.created.astimezone().strftime("%b %d %H:%M"),
                    "technique": s.technique,
                    "path": s.mode,
                    "prompt": s.prompt_version,
                    "model": r.model.split("/")[-1],
                    "result": s.status.replace("_", " "),
                    "calls": len(r.model_calls),
                    "tokens": r.prompt_tokens + r.completion_tokens,
                    "seconds": round(r.duration_s),
                }
                for s, r in zip(summaries, runs, strict=True)
            ]
        )
        st.caption(
            f"Read from {runs_dir} at {datetime.now(UTC):%H:%M} UTC. `detectforge export` writes every run, "
            "model call and tool call as CSV, with mean and spread per configuration."
        )


def _overview(runs_dir: Path, runs: list) -> None:
    today = calls_today(runs_dir)
    limit = get_settings().daily_request_limit
    passed = sum(r.status == "passed" for r in runs)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Agent runs", len(runs))
    c2.metric("Passed the gate", f"{passed}/{len(runs)}")
    c3.metric("Model calls", sum(len(r.model_calls) for r in runs), help="Each run's calls are capped.")
    tokens = sum(r.prompt_tokens + r.completion_tokens for r in runs)
    c4.metric("Tokens", _compact(tokens), help=f"{tokens:,} tokens in and out.")
    c5.metric("Calls today (UTC)", f"{today}/{limit}", help="The provider's daily limit for free models.")
    if today >= limit * 0.8:
        st.warning("Close to today's free request limit; it resets at midnight UTC.")


def _versions(runs: list) -> None:
    st.caption("Each prompt version was a response to failures on real runs (see the failure matrix).")
    by_version: dict[str, list] = {}
    for r in runs:
        by_version.setdefault(f"{r.prompt_version} · {r.mode}", []).append(r)
    table(
        [
            {
                "prompt · path": version,
                "runs": len(rs),
                "passed": pct(sum(r.status == "passed" for r in rs) / len(rs)),
                "model calls / run": f"{sum(len(r.model_calls) for r in rs) / len(rs):.1f}",
                "tokens / run": f"{sum(r.prompt_tokens + r.completion_tokens for r in rs) / len(rs):,.0f}",
                "seconds / run": f"{sum(r.duration_s for r in rs) / len(rs):.0f}",
            }
            for version, rs in sorted(by_version.items())
        ]
    )


def _failures(runs: list) -> None:
    model_calls = [c for r in runs for c in r.model_calls]
    c1, c2, c3 = st.columns(3)
    c1.metric("Failed model calls", sum(not c.ok for c in model_calls), help="After the SDK's own retries.")
    c2.metric("Answered by the fallback model", sum(c.used_fallback for c in model_calls))
    c3.metric("Answers cut off (output limit)", sum(c.finish_reason == "length" for c in model_calls))
    # One count per run and kind: a run that failed the same check twice counts once. Warnings never
    # stop a rule, so they aren't a reason it needed review.
    reasons = Counter(
        kind
        for r in runs
        if r.status != "passed"
        for kind in {_reason_kind(reason) for reason in r.reasons if not _is_warning(reason)}
    )
    if reasons:
        st.caption(
            'Why runs ended as "needs human review" instead of passing: each failed quality check or '
            "limit, counted once per run. A run can have several."
        )
        table([{"why a run needed human review": k, "runs": n} for k, n in reasons.most_common()])
    tool_errors = Counter(
        "tuning budget used up" if "budget" in (c.error or "") else c.tool
        for r in runs
        for c in r.tool_calls
        if not c.ok
    )
    if tool_errors:
        st.caption(
            "Tool calls the system refused and explained back to the agent: "
            + md(", ".join(f"{what} (x{n})" for what, n in tool_errors.most_common()))
        )


def _evaluation(data_dir: Path, runs_dir: Path) -> None:
    """The evaluation, as in the report: three arms on the test split, then the agent itself."""
    st.markdown("#### The question")
    st.caption(
        "Do community rules hold up against disguised attacks, and does the agent make them harder to evade "
        "without adding false alarms? The agent improves rules on some disguise types (tuning) and is judged "
        "on the others, which it never sees (held-out). The test techniques were run once, after the agent's "
        "prompts were frozen, so the numbers can't have been tuned to look good."
    )
    h = headline(data_dir, runs_dir)
    c1, c2, c3 = st.columns(3)
    with c1.container(border=True):
        st.markdown("**Arm 1 · community rules as published**")
        st.metric("Unseen variations caught", pct(h.community_unseen))
        st.caption(
            f"Mean over the {h.community_scored} of {h.community_rules} test rules that have unseen variations "
            '(the others are n/a, not 0% or 100%). The "before" everything is compared with.'
        )
    with c2.container(border=True):
        hd = h.hardened
        st.markdown("**Arm 2 · the same rules, hardened by the agent**")
        st.metric("Unseen variations caught", f"{pct(hd.before)} → {pct(hd.after)}")
        st.caption(
            f"{hd.runs} runs on {hd.rules} rules (3 each): only rules that miss something the agent can see "
            f"get hardened. {hd.passed} passed the checks, {hd.approved} approved, "
            f"{hd.new_false_alarm_runs} added a false alarm. The headline comparison with Arm 1."
        )
    with c3.container(border=True):
        wr = h.written
        st.markdown("**Arm 3 · rules the agent wrote itself**")
        st.metric("Unseen variations caught", f"{pct(wr.before)} → {pct(wr.after)}")
        st.caption(
            f"{wr.runs} runs with the technique's community rules hidden: the fallback when none exists. "
            f"{wr.passed} passed the checks, {wr.approved} approved, {wr.new_false_alarm_runs} runs raised a "
            "false alarm on unseen legitimate commands."
        )
    st.caption(
        "Arms 2 and 3 are on different rules, so they are not a ranking: hardening improves a rule that "
        "exists, writing covers a technique from nothing. Full tables: docs/report/results.md."
    )

    metrics = _json(data_dir / "eval" / "results" / "agent_metrics_test.json")
    if metrics:
        st.markdown("#### The agent itself (not just its rules)")
        st.caption(
            "Computed from every recorded step of every test run (scripts/agent_metrics.py): what it did on "
            "the way to a rule, not only the rule it produced."
        )
        rows = []
        for key, meaning in [
            ("success_passed_gate", "passed every automatic quality check"),
            ("approved_by_reviewer", "approved by a person"),
            ("recovered_after_rejection", "fixed its rule after the checks refused it"),
            ("pass_at_k", "succeeded in at least 1 of 3 tries (pass@3)"),
            ("pass_all_k", "succeeded in all 3 tries"),
            ("unsupported_claims", "explanations that claimed more than its own test showed"),
            ("runs_with_heldout_leak", "runs that ever saw held-out data (must be 0)"),
            ("runs_approved_without_human", "rules approved without a person (must be 0)"),
            ("tool_call_success", "tool calls that worked"),
            ("redundant_scoring_calls", "tool calls that re-tested the exact same rule"),
        ]:
            row = {"what it measures": meaning}
            for arm in ("hardened", "written"):
                row[arm] = str((metrics.get(arm) or {}).get(key, "n/a"))
            rows.append(row)
        table(rows)

    ablation = _json(data_dir / "eval" / "results" / "agent_metrics_dev_budget25.json")
    dev = _json(data_dir / "eval" / "results" / "agent_metrics_dev.json")
    if ablation and dev:
        st.markdown("#### Ablation: does a bigger budget help? (dev techniques only)")
        a, b = dev.get("written") or {}, ablation.get("written") or {}
        table(
            [
                {"model calls per written rule": "15 (frozen)", "passed the checks": a.get("success_passed_gate"),
                 "unseen variations caught": pct(a.get("heldout_after_mean"))},
                {"model calls per written rule": "25", "passed the checks": b.get("success_passed_gate"),
                 "unseen variations caught": pct(b.get("heldout_after_mean"))},
            ]
        )  # fmt: skip
        st.caption(
            "More calls let more rules pass the checks, but not catch more unseen variations: budget buys "
            "persistence, not generalization. Run on dev only; the test result stays at the frozen budget."
        )

    path = data_dir / "eval" / "results" / "arm1_community.json"
    try:
        arm = ArmResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError):
        return
    with st.expander("Arm 1 by disguise type (all 27 rules)"):
        st.caption(
            "Which tricks beat community rules. Omission and reordering rarely work against them; inserted "
            "characters and swapped flags often do. Recoding has a single example, too few to judge."
        )
        table(
            [{"disguise type": t, "caught": pct(v)} for t, v in arm.resistance_by_transform.items()]
            + [
                {"disguise type": f"{s} split", "caught": pct(v)}
                for s, v in arm.resistance_by_mutation_split.items()
            ]
        )


def _json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _compact(n: int) -> str:
    """1318200 -> 1.3M, 45600 -> 45.6k: fits a metric card."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    return f"{n / 1_000:.1f}k" if n >= 1_000 else str(n)


_CHECK_KINDS = {
    "evasion_resistance": "catches too few tuning variations (below 80%)",
    "false_alarms": "fires on legitimate tuning commands",
    "case_insensitive_regexes": "case-sensitive regex on case-insensitive Windows fields",
    "no_unusual_characters": "copied unusual characters from the attacks",
    "detects_unmutated_attacks": "misses some plain (unmutated) attacks",
    "no_bypassable_exclusions": "an exclusion an attacker can add for free",
    "no_lost_attacks": "stopped catching an attack the original caught",
    "no_new_false_alarms": "new false alarms versus the original",
    "valid": "never produced a rule that could be evaluated",
    "deployable": "can't be converted for the SIEM",
}


def _is_warning(reason: str) -> bool:
    return ": warning" in reason.lower()


def _reason_kind(reason: str) -> str:
    """Group free-text reasons into a few kinds a person can scan (a check's name, not its numbers)."""
    name = reason.split(":", 1)[0].strip()
    if name in _CHECK_KINDS:
        return f"quality check: {_CHECK_KINDS[name]}"
    text = reason.lower()
    for needle, kind in [
        ("llm unavailable", "model unavailable (after retries and fallback)"),
        ("output tokens", "answer cut off by the output limit"),
        ("rejected every submission", "quality gate rejected every submission"),
        ("without submitting", "stopped without submitting a rule"),
        ("model call budget", "model-call budget used up"),
        ("token budget", "token budget used up"),
        ("timeout", "timed out"),
    ]:
        if needle in text:
            return kind
    return reason[:80]
