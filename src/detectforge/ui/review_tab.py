"""Review: an inbox of the agent's proposals, and one decision at a time with its evidence.

Left, the proposals (waiting first). Right, the open one: a plain-language verdict, the few numbers a
reviewer decides on, what changed, then the deeper evidence folded away (every variation, the quality
checks, what the agent did, the audit trail), and the decision itself. Evaluation vocabulary stays in
the audit trail; the verdict says "variations the agent never saw", not "held-out".
"""

import difflib
import json
from pathlib import Path
from typing import Literal

import streamlit as st
from pydantic import BaseModel, ValidationError

from detectforge.agent.runner import HardeningOutcome
from detectforge.config import get_settings
from detectforge.review import (
    ReviewAuthError,
    ReviewDecision,
    RunSummary,
    decide,
    decisions,
    latest_prompt_versions,
    list_runs,
    load_run,
    parse_reviewer_keys,
)
from detectforge.ui.components import delta_pct, export_view, md, pct, rule_title, table
from detectforge.ui.lookalikes import Lookalike, firing_lookalikes, load_lookalikes
from detectforge.ui.navigation import header

FILTERS = {"pending review": "Waiting", "approved": "Approved", "rejected": "Rejected", "all": "All"}


class Verdict(BaseModel):
    """What the reviewer should know first, in one headline and one or two sentences."""

    kind: Literal["success", "warning", "error", "info"]
    headline: str
    text: str


def verdict(
    outcome: HardeningOutcome, decision: ReviewDecision | None, extra_hits: list[Lookalike] | None = None
) -> Verdict:
    """extra_hits: everyday commands outside the dataset that the proposed rule fires on."""
    run, heldout = outcome.run, outcome.heldout_evaluation
    if decision is not None:
        when = f"{decision.decided_at.astimezone():%b %d %H:%M}"
        if decision.decision == "approved":
            return Verdict(
                kind="success",
                headline="Approved",
                text=f"Approved by {md(decision.reviewer)} on {when}; the rule is saved in approved/, "
                "ready to deploy. You can still change the decision below.",
            )
        return Verdict(
            kind="info",
            headline="Rejected",
            text=f"Rejected by {md(decision.reviewer)} on {when}. You can still change the decision below.",
        )
    if not run.final_rule_yaml:
        return Verdict(
            kind="error",
            headline="Nothing to approve",
            text="The agent produced no valid rule. Reject it to clear it from the queue.",
        )
    new_alarms = heldout.new_false_alarm_event_ids if heldout else []
    if new_alarms:
        return Verdict(
            kind="error",
            headline="Check before approving",
            text=f"It raises {len(new_alarms)} new false alarm(s) on legitimate commands the agent never "
            f"saw: {', '.join(new_alarms)}. Look at them below before approving.",
        )
    if extra_hits:
        return Verdict(
            kind="error",
            headline="Check before approving",
            text=f"It fires on {len(extra_hits)} everyday legitimate command(s) that aren't in the test "
            "data, so the quality checks couldn't see them. Look at them below: approving means these "
            "would raise alerts.",
        )
    failed = [c.name.replace("_", " ") for c in run.gate.checks if c.blocking and not c.passed]
    if failed:
        return Verdict(
            kind="warning",
            headline="Needs your judgement",
            text=f"The quality checks did not accept it ({', '.join(failed)}). Approving overrides them, "
            "so say why in the comment.",
        )
    return Verdict(kind="success", headline="Ready for your decision", text=_gain(heldout))


def _gain(heldout) -> str:
    if heldout is None or heldout.mutated_attacks == 0:
        return (
            "There are no attacker variations the agent never saw for this technique, so the improvement "
            "can't be measured on unseen ones. No new false alarms."
        )
    before, after = heldout.evasion_resistance_before, heldout.evasion_resistance_after
    return (
        f"It catches {pct(after)} of the attacker variations the agent never saw (the rule before: "
        f"{pct(before)}), with no new false alarms on legitimate commands."
    )


def review_tab(runs_dir: Path) -> None:
    header(
        "review", "Proposals waiting for a decision, with the evidence. Nothing ships until you approve it."
    )
    # Shown first: after a decision the run may leave the current filter (e.g. "Waiting").
    if message := st.session_state.pop("review_message", None):
        (st.error if message.startswith("Could not") else st.success)(message)
    runs = list_runs(runs_dir)
    if not runs:
        st.info("No agent runs yet. Ask the agent from the Rules area, or run `detectforge harden`.")
        return

    latest = latest_prompt_versions(runs)
    left, right = st.columns([3, 1], vertical_alignment="bottom")
    only_latest = right.toggle(
        "Current prompts only",
        value=True,
        key="review_latest",
        help=f"Runs from older prompt versions are kept as history (see the Lab) but hidden here. "
        f"Current: {', '.join(sorted(latest))}.",
    )
    runs = [r for r in runs if not only_latest or r.prompt_version in latest]
    counts = {k: sum(_state(r) == k for r in runs) for k in FILTERS if k != "all"}
    counts["all"] = len(runs)
    show = left.radio(
        "Show",
        list(FILTERS),
        format_func=lambda k: f"{FILTERS[k]} ({counts[k]})",
        horizontal=True,
        key="review_show",
        label_visibility="collapsed",
    )
    runs = [r for r in runs if show == "all" or _state(r) == show]
    if not runs:
        st.info("Nothing is waiting for a decision." if show == "pending review" else "No runs here.")
        return

    ids = [r.trace_id for r in runs]
    if st.session_state.get("review_pick") not in ids:
        st.session_state["review_pick"] = ids[0]
    by_id = {r.trace_id: r for r in runs}
    titles = {r.trace_id: _title(runs_dir, r) for r in runs}
    inbox, detail = st.columns([1, 2.6], gap="large")
    with inbox, st.container(key="inbox"):
        chosen = st.radio(
            "Proposals",
            ids,
            format_func=lambda i: md(titles[i]),
            captions=[_line(by_id[i]) for i in ids],
            key="review_pick",
            label_visibility="collapsed",
        )
    with detail:
        outcome = load_run(runs_dir, chosen)
        history = decisions(runs_dir, chosen)
        run_detail(outcome, titles[chosen], history[-1] if history else None)
        decision_form(runs_dir, outcome, history)
        if outcome.run.final_rule_yaml:
            export_view(outcome.run.final_rule_yaml, f"proposal-{outcome.run.trace_id[:8]}")


def _state(r: RunSummary) -> str:
    return r.decision.decision if r.decision else "pending review"


def _title(runs_dir: Path, r: RunSummary) -> str:
    run = load_run(runs_dir, r.trace_id).run
    return rule_title(run.final_rule_yaml or run.original_rule_yaml, f"New rule for {r.technique}")


def _line(r: RunSummary) -> str:
    """The inbox row's second line: technique, path, unseen variations before → after, state."""
    path = "new rule" if r.mode == "write" else "hardened"
    unseen = (
        f"unseen {pct(r.heldout_before)} → {pct(r.heldout_after)}" if r.heldout_mutations else "unseen n/a"
    )
    state = {"approved": "✓ approved", "rejected": "✗ rejected"}.get(_state(r), "waiting")
    return f"{r.technique} · {path} · {unseen} · {state}"


def run_detail(outcome: HardeningOutcome, title: str, decision: ReviewDecision | None) -> None:
    run, heldout = outcome.run, outcome.heldout_evaluation
    path = "wrote a new rule" if run.mode == "write" else "hardened a community rule"
    st.markdown(f"### {md(title)}")
    st.caption(f"{run.technique} · the agent {path}")

    extra_hits = firing_lookalikes(run.final_rule_yaml, load_lookalikes(get_settings().data_dir))
    v = verdict(outcome, decision, extra_hits)
    getattr(st, v.kind)(f"**{v.headline}.** {v.text}")
    if extra_hits:
        with st.container(border=True):
            st.markdown("**Fires on everyday commands outside the test data**")
            for x in extra_hits:
                st.code(x.cmd, language=None, wrap_lines=True)
                st.caption(f"Legitimate: {md(x.why)}.")

    blocking = [c for c in run.gate.checks if c.blocking]
    new_alarms = heldout.new_false_alarm_event_ids if heldout else []
    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
        "Unseen variations",
        pct(heldout.evasion_resistance_after if heldout else None),
        delta=delta_pct(heldout.evasion_resistance_before, heldout.evasion_resistance_after)
        if heldout
        else None,
        help="Share caught of attacker variations of types the agent never saw while working "
        "(the held-out set), "
        "measured after the run without the agent. The fair test.",
    )
    c2.metric(
        "Tuning variations",
        pct(run.tuning_evasion_resistance_after),
        delta=delta_pct(run.tuning_evasion_resistance_before, run.tuning_evasion_resistance_after),
        help="Share caught of the attacker variations the agent was allowed to test against "
        "(the tuning set).",
    )
    c3.metric(
        "New false alarms",
        len(new_alarms) if heldout else "n/a",
        help="Legitimate look-alike commands the rule now fires on, among ones the agent never saw.",
    )
    c4.metric(
        "Quality checks",
        f"{sum(c.passed for c in blocking)}/{len(blocking)}",
        help="Deterministic checks every proposal must pass (validity, deployability, overfitting, "
        "no lost attacks, no new false alarms on the tuning set).",
    )

    if run.rationale:
        with st.expander("Why the agent changed it"):
            # Model output: shown literally, so an injected link or "approved" banner can't render.
            st.markdown(md(run.rationale))
    if run.mode == "write":
        st.markdown(
            "**Written by the agent.** Community rules for this technique were hidden from it (it may "
            "only look at other techniques' rules for Sigma style), so the detection logic is its own. "
            'This is the path when no usable community rule exists, and the evaluation\'s "written" arm.'
        )
        if run.final_rule_yaml:
            st.code(run.final_rule_yaml, language="yaml")
        else:
            st.info("The agent produced no valid rule. Nothing to approve.")
    else:
        _hardening_diff(run)

    if heldout:
        with st.expander("Every variation, by type"):
            st.caption(
                "Variation types the agent never saw (evaluation only). Rows with no attacks are left out."
            )
            table(
                [
                    {
                        "variation type": t,
                        "attacks": d.attacks,
                        "caught before": pct(d.resistance_before),
                        "caught after": pct(d.resistance_after),
                    }
                    for t, d in heldout.per_transform.items()
                    if d.attacks
                ]
            )
            if new_alarms:
                st.markdown("New false alarms: " + md(", ".join(new_alarms)))
    with st.expander(f"Quality checks ({sum(c.passed for c in blocking)}/{len(blocking)} passed)"):
        table(
            [
                {
                    "check": c.name.replace("_", " "),
                    "result": "pass" if c.passed else ("FAIL" if c.blocking else "warning"),
                    "detail": c.detail,
                }
                for c in run.gate.checks
            ]
        )
    with st.expander(
        f"What the agent did: {len(run.model_calls)} model calls, {len(run.tool_calls)} tool calls, "
        f"{run.prompt_tokens + run.completion_tokens:,} tokens, {run.duration_s:.0f}s"
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
    with st.expander("Audit trail"):
        st.caption(
            f"Run `{run.trace_id}` · model `{run.model}` · prompt `{run.prompt_version}` · "
            f"result `{run.status}` ({run.final_source.replace('_', ' ')})"
        )
        if run.reasons:
            st.caption("Why it needed review: " + md("; ".join(run.reasons)))
        if p := outcome.provenance:
            commit = p.git_commit or "unknown"
            if p.git_dirty:
                commit += " + uncommitted changes"
            st.caption(
                f"Setup `{p.setup_key}` · code `{p.code_sha}` (commit {commit}) · {p.event_count} events "
                f"`{p.events_sha}` · budgets {p.budgets}"
            )


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


def decision_form(runs_dir: Path, outcome: HardeningOutcome, history: list[ReviewDecision]) -> None:
    trace_id = outcome.run.trace_id
    st.markdown("**Your decision**" if not history else "**Decision history**")
    for d in history:
        st.caption(
            f"{d.decided_at.astimezone():%b %d %H:%M} — **{d.decision}** by {md(d.reviewer)}"
            + (f": {md(d.comment)}" if d.comment else "")
        )
    if outcome.run.status != "passed":
        st.caption("The quality checks did not accept this rule; approving it overrides them, so say why.")

    try:
        keys = parse_reviewer_keys(get_settings().reviewer_keys)
        off = None if keys else "no reviewer keys are set (DETECTFORGE_REVIEWER_KEYS in .env)"
    except ValueError as e:
        keys, off = {}, f"the reviewer keys are misconfigured: {e}"
    if off:
        st.caption(f"Approving and rejecting are off here: {off}.")
    with st.container(border=True):
        k, c = st.columns([1, 2])
        reviewer_key = k.text_input(
            "Reviewer key", key="reviewer_key", type="password", disabled=bool(off),
            help="Your personal key. The decision is recorded under the name it belongs to.",
        )  # fmt: skip
        comment = c.text_input(
            "Comment", key=f"comment_{trace_id}", disabled=bool(off), placeholder="Why approve or reject"
        )
        b1, b2, _ = st.columns([1, 1, 4])
        for column, label, decision, kind in [
            (b1, "Approve", "approved", "primary"),
            (b2, "Reject", "rejected", "secondary"),
        ]:
            column.button(
                label,
                type=kind,
                key=f"{decision}_{trace_id}",
                disabled=bool(off),
                width="stretch",
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
