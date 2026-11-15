"""Review tab: every agent run, what it changed, the evidence, and the human's approve/reject."""

import difflib
import json
from pathlib import Path

import streamlit as st
from pydantic import ValidationError

from detectforge.agent.runner import HardeningOutcome
from detectforge.review import decisions, list_runs, load_run, record_decision
from detectforge.ui.components import delta_pct, pct, table


def review_tab(runs_dir: Path) -> None:
    st.subheader("4 · Review agent runs (a human approves every change)")
    runs = list_runs(runs_dir)
    if not runs:
        st.info("No agent runs yet. Ask the agent from the Harden tab, or run `detectforge harden`.")
        return

    table(
        [
            {
                "when": r.created.astimezone().strftime("%b %d %H:%M"),
                "technique": r.technique,
                "agent result": r.status.replace("_", " "),
                "tuning (before → after)": f"{pct(r.tuning_before)} → {pct(r.tuning_after)}",
                "held-out (before → after)": f"{pct(r.heldout_before)} → {pct(r.heldout_after)}",
                "model calls": r.model_calls,
                "decision": r.decision.decision if r.decision else "pending review",
            }
            for r in runs
        ]
    )
    chosen = st.selectbox(
        "Open a run",
        runs,
        format_func=lambda r: (
            f"{r.created.astimezone():%b %d %H:%M} · {r.technique} · {r.status.replace('_', ' ')} · "
            f"{r.decision.decision if r.decision else 'pending review'}"
        ),
    )
    outcome = load_run(runs_dir, chosen.trace_id)
    st.divider()
    run_detail(outcome)
    st.divider()
    decision_form(runs_dir, outcome)


def run_detail(outcome: HardeningOutcome) -> None:
    run, heldout = outcome.run, outcome.heldout_evaluation
    st.caption(f"Run `{run.trace_id}` · model `{run.model}` · prompt `{run.prompt_version}`")
    if run.status == "passed":
        st.success("The quality gate accepted the agent's rule. It still needs your decision.")
    else:
        st.warning("Needs human review: " + "; ".join(run.reasons))
    if run.rationale:
        st.markdown(f"**Agent's explanation:** {run.rationale}")

    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Tuning evasion resistance",
        pct(run.tuning_evasion_resistance_after),
        delta=delta_pct(run.tuning_evasion_resistance_before, run.tuning_evasion_resistance_after),
        help="On the mutations the agent was allowed to see.",
    )
    c2.metric(
        "Held-out evasion resistance",
        pct(heldout.evasion_resistance_after if heldout else None),
        delta=delta_pct(heldout.evasion_resistance_before, heldout.evasion_resistance_after)
        if heldout
        else None,
        help="The fair test: mutation types the agent never saw. Computed after the run.",
    )
    c3.metric(
        "False alarms (tuning)",
        run.tuning_false_alarms_after,
        delta=run.tuning_false_alarms_after - run.tuning_false_alarms_before,
        delta_color="inverse",
    )

    st.markdown("**What changed**")
    diff = "\n".join(
        difflib.unified_diff(
            run.original_rule_yaml.splitlines(),
            run.final_rule_yaml.splitlines(),
            "original (community rule)",
            f"proposed ({run.final_source.replace('_', ' ')})",
            lineterm="",
        )
    )
    if diff:
        st.code(diff, language="diff")
    else:
        st.info("No change: the proposal is the original rule.")
    left, right = st.columns(2)
    with left.expander("Original rule"):
        st.code(run.original_rule_yaml, language="yaml")
    with right.expander("Proposed rule"):
        st.code(run.final_rule_yaml, language="yaml")

    st.markdown("**Quality gate**")
    table(
        [
            {
                "check": c.name,
                "result": "pass" if c.passed else ("FAIL" if c.blocking else "warning"),
                "detail": c.detail,
            }
            for c in run.gate.checks
        ]
    )

    if heldout:
        st.markdown("**Held-out mutations, per type** (evaluation only, never shown to the agent)")
        table(
            [
                {
                    "transform": t,
                    "attacks": d.attacks,
                    "before": pct(d.resistance_before),
                    "after": pct(d.resistance_after),
                }
                for t, d in heldout.per_transform.items()
                if d.attacks
            ]
        )

    with st.expander(
        f"What the agent did: {len(run.model_calls)} model calls, {len(run.tool_calls)} tool calls, "
        f"{run.prompt_tokens + run.completion_tokens} tokens, {run.duration_s}s"
    ):
        table(
            [
                {
                    "#": i,
                    "model": c.model,
                    "ok": "yes" if c.ok else f"NO: {c.error}",
                    "seconds": round(c.latency_ms / 1000, 1),
                    "tokens in/out": f"{c.prompt_tokens}/{c.completion_tokens}",
                    "fallback": "yes" if c.used_fallback else "",
                }
                for i, c in enumerate(run.model_calls, start=1)
            ]
        )
        table(
            [
                {"#": i, "tool": c.tool, "ok": "yes" if c.ok else f"NO: {c.error}", "ms": c.latency_ms}
                for i, c in enumerate(run.tool_calls, start=1)
            ]
        )
        if outcome.trace_url:
            st.markdown(f"[Open the full trace in Langfuse]({outcome.trace_url})")

    if run.transcript:
        if st.toggle("Show the agent's conversation", key=f"transcript_{run.trace_id}"):
            conversation_view(run.transcript)
    else:
        st.caption("This run was saved before conversations were recorded.")


MAX_SHOWN = 3000


def conversation_view(transcript: list[dict]) -> None:
    """Every step the agent took. Model text is shown as plain text: it's untrusted output."""
    step = 0
    for message in transcript:
        role, content = message.get("role"), message.get("content") or ""
        if role == "system":
            st.markdown("**Instructions given to the agent**")
            st.text(_shorten(content))
        elif role == "user":
            st.markdown("**Task**" if step == 0 else "**Reminder from the loop**")
            st.code(_shorten(content), language=None)
        elif role == "assistant":
            step += 1
            st.markdown(f"**Step {step}: the agent**")
            if content.strip():
                st.text(_shorten(content))
            for call in message.get("tool_calls") or []:
                name, arguments = call["function"]["name"], call["function"]["arguments"]
                st.markdown(f"calls `{name}`")
                rule = _rule_argument(arguments)
                st.code(_shorten(rule or arguments), language="yaml" if rule else "json")
        elif role == "tool":
            st.markdown("result:")
            st.code(_shorten(_pretty(content)), language="json")


def _rule_argument(arguments: str) -> str | None:
    try:
        value = json.loads(arguments).get("rule_yaml")
    except (json.JSONDecodeError, AttributeError):
        return None
    return value if isinstance(value, str) else None


def _pretty(content: str) -> str:
    try:
        return json.dumps(json.loads(content), indent=1, ensure_ascii=False)
    except json.JSONDecodeError:
        return content


def _shorten(text: str) -> str:
    return (
        text
        if len(text) <= MAX_SHOWN
        else text[:MAX_SHOWN] + f"\n… ({len(text) - MAX_SHOWN} more characters)"
    )


def decision_form(runs_dir: Path, outcome: HardeningOutcome) -> None:
    trace_id = outcome.run.trace_id
    st.markdown("**Your decision**")
    history = decisions(runs_dir, trace_id)
    for d in history:
        st.caption(
            f"{d.decided_at.astimezone():%b %d %H:%M} — **{d.decision}** by {d.reviewer}"
            + (f": {d.comment}" if d.comment else "")
        )
    if outcome.run.status != "passed":
        st.caption("The gate did not accept this rule; approving it overrides the gate, so say why.")

    reviewer = st.text_input("Reviewer", key="reviewer")
    comment = st.text_area("Comment", key=f"comment_{trace_id}", height=80)
    c1, c2, _ = st.columns([1, 1, 4])
    c1.button(
        "Approve",
        type="primary",
        key=f"approve_{trace_id}",
        on_click=_decide,
        args=(runs_dir, trace_id, "approved", reviewer, comment),
    )
    c2.button(
        "Reject",
        key=f"reject_{trace_id}",
        on_click=_decide,
        args=(runs_dir, trace_id, "rejected", reviewer, comment),
    )
    if message := st.session_state.pop("review_message", None):
        (st.error if message.startswith("Could not") else st.success)(message)


def _decide(runs_dir: Path, trace_id: str, decision: str, reviewer: str, comment: str) -> None:
    try:
        record = record_decision(runs_dir, trace_id, decision, reviewer, comment)
    except ValidationError:
        st.session_state["review_message"] = "Could not save: enter your name as reviewer."
        return
    where = f" Saved to {runs_dir / 'approved' / (trace_id + '.yml')}." if decision == "approved" else ""
    st.session_state["review_message"] = f"Rule {record.status}.{where}"
