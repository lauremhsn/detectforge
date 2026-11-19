"""Lab (agent operations): what the agent costs, how fast it is, how often it fails, and why.

Read from the saved runs (every model and tool call is recorded in them), so it works without the
tracing backend. Free models cost nothing in money; the budget that matters is the provider's daily
request limit, shown next to today's usage.
"""

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st

from detectforge.config import get_settings
from detectforge.review import calls_today, list_runs, load_run
from detectforge.ui.components import md, pct, table
from detectforge.ui.navigation import header


def operations_page(runs_dir: Path) -> None:
    header(
        "operations",
        "The research side: what the agent costs, how fast it is, how often it fails, per prompt version. "
        "Which events rules are tested on is set in the sidebar (the arrow at the top left).",
    )
    summaries = list_runs(runs_dir)
    if not summaries:
        st.info("No agent runs yet.")
        return
    runs = [load_run(runs_dir, s.trace_id).run for s in summaries]

    today = calls_today(runs_dir)
    limit = get_settings().daily_request_limit
    passed = sum(r.status == "passed" for r in runs)
    calls = sum(len(r.model_calls) for r in runs)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Agent runs", len(runs))
    c2.metric("Passed the gate", f"{passed}/{len(runs)}")
    c3.metric("Model calls", calls, help="Each run's calls are capped by its budget.")
    c4.metric("Tokens", f"{sum(r.prompt_tokens + r.completion_tokens for r in runs):,}")
    c5.metric("Calls today (UTC)", f"{today}/{limit}", help="The provider's daily limit for free models.")
    if today >= limit * 0.8:
        st.warning("Close to today's free request limit; it resets at midnight UTC.")

    st.subheader("Per prompt version")
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

    st.subheader("Failures and how they were handled")
    model_calls = [c for r in runs for c in r.model_calls]
    failed = [c for c in model_calls if not c.ok]
    c1, c2, c3 = st.columns(3)
    c1.metric("Failed model calls", len(failed), help="After the SDK's own retries.")
    c2.metric("Answered by the fallback model", sum(c.used_fallback for c in model_calls))
    c3.metric("Answers cut off (output limit)", sum(c.finish_reason == "length" for c in model_calls))
    reasons = Counter(_reason_kind(reason) for r in runs if r.status != "passed" for reason in r.reasons)
    if reasons:
        table([{"why a run needed human review": k, "runs": n} for k, n in reasons.most_common()])
    tool_errors = Counter(c.tool for r in runs for c in r.tool_calls if not c.ok)
    if tool_errors:
        st.caption(
            "Tool calls the agent got wrong (refused and fed back to it): "
            + md(", ".join(f"{tool} (x{n})" for tool, n in tool_errors.most_common()))
        )

    st.subheader("Runs")
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
    st.caption(f"Read from {runs_dir} at {datetime.now(UTC):%H:%M} UTC.")


def _reason_kind(reason: str) -> str:
    """Group free-text reasons into a few kinds a person can scan."""
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
