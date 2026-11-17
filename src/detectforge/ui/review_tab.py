"""Review tab: every agent run, what it changed, the evidence, and the human's approve/reject."""

import difflib
import json
from pathlib import Path

import streamlit as st
from pydantic import ValidationError

from detectforge.agent.runner import HardeningOutcome
from detectforge.config import get_settings
from detectforge.review import (
    ReviewAuthError,
    decide,
    decisions,
    latest_prompt_versions,
    list_runs,
    load_run,
    parse_reviewer_keys,
)
from detectforge.ui.components import delta_pct, export_view, md, pct, table
from detectforge.ui.navigation import header


def review_tab(runs_dir: Path) -> None:
    header(
        "review",
        "Proposals waiting for a decision, with the evidence. Nothing ships until a reviewer approves it.",
    )
    # Shown first: after a decision the run may leave the current filter (e.g. "pending review").
    if message := st.session_state.pop("review_message", None):
        (st.error if message.startswith("Could not") else st.success)(message)
    runs = list_runs(runs_dir)
    if not runs:
        st.info("No agent runs yet. Ask the agent from the Harden tab, or run `detectforge harden`.")
        return

    def state(r) -> str:
        return r.decision.decision if r.decision else "pending review"

    latest = latest_prompt_versions(runs)
    only_latest = st.toggle(
        f"Only the current prompts ({', '.join(sorted(latest))})",
        value=True,
        key="review_latest",
        help="Runs made with older prompt versions are kept as history (and in Agent operations) but "
        "hidden here: they were replaced by runs of the current prompt.",
    )
    hidden = sum(r.prompt_version not in latest for r in runs) if only_latest else 0
    runs = [r for r in runs if not only_latest or r.prompt_version in latest]
    counts = {s: sum(state(r) == s for r in runs) for s in ("pending review", "approved", "rejected")}
    c1, c2, c3 = st.columns(3)
    c1.metric("Waiting for review", counts["pending review"])
    c2.metric("Approved", counts["approved"])
    c3.metric("Rejected", counts["rejected"])
    if hidden:
        st.caption(f"{hidden} run(s) from older prompt versions hidden.")
    show = st.radio(
        "Show", ["pending review", "all", "approved", "rejected"], horizontal=True, key="review_show"
    )
    runs = [r for r in runs if show == "all" or state(r) == show]
    if not runs:
        st.info(f"No runs {'waiting for review' if show == 'pending review' else show}.")
        return

    table(
        [
            {
                "when": r.created.astimezone().strftime("%b %d %H:%M"),
                "technique": r.technique,
                "path": "write" if r.mode == "write" else "harden",
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
    if outcome.run.final_rule_yaml:
        export_view(outcome.run.final_rule_yaml, f"proposal-{outcome.run.trace_id[:8]}")
    decision_form(runs_dir, outcome)


def run_detail(outcome: HardeningOutcome) -> None:
    run, heldout = outcome.run, outcome.heldout_evaluation
    path = "wrote a new rule" if run.mode == "write" else "hardened a community rule"
    st.caption(f"Run `{run.trace_id}` · {path} · model `{run.model}` · prompt `{run.prompt_version}`")
    if p := outcome.provenance:
        commit = p.git_commit or "unknown"
        if p.git_dirty:
            commit += " + uncommitted changes"
        st.caption(
            f"Setup `{p.setup_key}` · code `{p.code_sha}` (commit {commit}) · {p.event_count} events "
            f"`{p.events_sha}` · budgets {p.budgets}"
        )
    if run.status == "passed":
        st.success("The quality gate accepted the agent's rule. It still needs your decision.")
    else:
        st.warning("Needs human review: " + md("; ".join(run.reasons)))
    if heldout and heldout.new_false_alarm_event_ids:
        st.error(
            f"The proposed rule raises {len(heldout.new_false_alarm_event_ids)} new false alarm(s) on "
            "held-out benign events that the agent and the gate never saw: "
            + ", ".join(heldout.new_false_alarm_event_ids)
            + ". Check these before approving."
        )
    if run.rationale:
        # Model output: shown literally, so an injected link or "approved" banner can't render.
        st.markdown(f"**Agent's explanation:** {md(run.rationale)}")

    c1, c2, c3, c4 = st.columns(4)
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
    c4.metric(
        "False alarms (held-out)",
        heldout.false_alarms_after if heldout else "n/a",
        delta=heldout.false_alarms_after - heldout.false_alarms_before if heldout else None,
        delta_color="inverse",
        help="On benign look-alikes the agent never saw. Computed after the run.",
    )

    if run.mode == "write":
        st.markdown(
            "**New rule** (no usable community rule: the agent wrote this from scratch, with the "
            'technique\'s community rules hidden; "before" is having no rule)'
        )
        if run.final_rule_yaml:
            st.code(run.final_rule_yaml, language="yaml")
        else:
            st.info("The agent produced no valid rule. Nothing to approve.")
    else:
        _hardening_diff(run)

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
                    "cut off": "yes (output limit)" if c.finish_reason == "length" else "",
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


def _hardening_diff(run) -> None:
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
            f"{d.decided_at.astimezone():%b %d %H:%M} — **{d.decision}** by {md(d.reviewer)}"
            + (f": {md(d.comment)}" if d.comment else "")
        )
    if outcome.run.status != "passed":
        st.caption("The gate did not accept this rule; approving it overrides the gate, so say why.")

    try:
        keys = parse_reviewer_keys(get_settings().reviewer_keys)
        off = None if keys else "no reviewer keys are set (DETECTFORGE_REVIEWER_KEYS in .env)"
    except ValueError as e:
        keys, off = {}, f"the reviewer keys are misconfigured: {e}"
    if off:
        st.caption(f"Approving and rejecting are off here: {off}.")
    reviewer_key = st.text_input(
        "Reviewer key", key="reviewer_key", type="password", disabled=bool(off),
        help="Your personal key. The decision is recorded under the name it belongs to.",
    )  # fmt: skip
    comment = st.text_area("Comment", key=f"comment_{trace_id}", height=80, disabled=bool(off))
    c1, c2, _ = st.columns([1, 1, 4])
    for column, label, decision, kind in [
        (c1, "Approve", "approved", "primary"),
        (c2, "Reject", "rejected", "secondary"),
    ]:
        column.button(
            label,
            type=kind,
            key=f"{decision}_{trace_id}",
            disabled=bool(off),
            on_click=_decide,
            args=(runs_dir, trace_id, decision, reviewer_key, keys, comment),
        )


def _decide(
    runs_dir: Path, trace_id: str, decision: str, reviewer_key: str, keys: dict[str, str], comment: str
) -> None:
    try:
        record = decide(runs_dir, trace_id, decision, reviewer_key, keys, comment)
    except ReviewAuthError as e:
        st.session_state["review_message"] = f"Could not save: {e}."
        return
    except ValidationError:
        st.session_state["review_message"] = "Could not save: the comment is too long."
        return
    finally:
        st.session_state["reviewer_key"] = ""  # never keep a key in the session after use
    where = f" Saved to {runs_dir / 'approved' / (trace_id + '.yml')}." if decision == "approved" else ""
    st.session_state["review_message"] = f"Rule {record.status}.{where}"
