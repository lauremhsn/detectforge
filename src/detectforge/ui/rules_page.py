"""Rules: pick one rule, test it against attacker variations, then harden it (by hand or with the agent).

Three guided steps on one page, with the rule under test always shown at the top. Every number comes
from the same library functions as the CLI (search, validate_rule, run, compare).
"""

import streamlit as st
import yaml

from detectforge.config import get_settings
from detectforge.harness import run
from detectforge.harness.compare import compare, evasion_resistance
from detectforge.reference.index import ReferenceIndex, techniques_from_tags
from detectforge.rules.validate import validate_rule
from detectforge.schemas import TRANSFORMS, Event, Scorecard
from detectforge.ui.agent_panel import agent_panel
from detectforge.ui.components import export_view, md, pct, table
from detectforge.ui.navigation import header, open_rule

STEPS = {
    "pick": "① Pick a rule",
    "test": "② Test it against evasions",
    "harden": "③ Harden it",
}


def rules_page(events: list[Event], all_events: list[Event], index: ReferenceIndex | str) -> None:
    header(
        "rules",
        "Pick a detection rule, measure how many attacker variations it still catches, then make it "
        "harder to evade. Changes only become real after a reviewer approves them.",
    )
    if label := st.session_state.get("rule_label"):
        st.info(f"**Rule under test:** {md(label)}")
    st.session_state.setdefault("rules_step", "pick")
    step = st.radio(
        "Step",
        list(STEPS),
        format_func=STEPS.get,
        horizontal=True,
        key="rules_step",
        label_visibility="collapsed",
    )
    st.divider()
    if step == "pick":
        pick_step(index)
    elif step == "test":
        test_step(events)
    else:
        harden_step(events, all_events, index if isinstance(index, ReferenceIndex) else None)


# ---- ① pick ----------------------------------------------------------------------------------


def pick_step(index: ReferenceIndex | str) -> None:
    if isinstance(index, str):
        st.info(index)
    else:
        st.caption(
            f"Community rules: SigmaHQ {index.release}, {len(index.rules)} Windows process-creation rules"
        )
        st.session_state.setdefault("find_technique", "T1053.005")
        c1, c2, c3 = st.columns([1, 2, 1])
        technique = c1.text_input("ATT&CK technique", key="find_technique")
        query = c2.text_input("Keywords (optional)", "schtasks create")
        limit = c3.slider("Max results", 1, 20, 8)
        exclude = st.checkbox(
            "Hide this technique's rules (as the agent sees it when writing a new rule)",
            help="For evaluating agent-written rules: the agent learns Sigma style from other rules only.",
        )
        try:
            hits = index.search(
                technique=None if exclude else (technique or None),
                query=query or None,
                limit=limit,
                exclude_technique=technique if exclude else None,
            )
        except ValueError as e:
            st.error(md(e))
            hits = []
        if not any(h.rule.usable for h in hits):
            st.warning(
                "No usable community rule here. DetectForge would write a new one: use **New request** "
                "for this technique."
            )
        if hits:
            table(
                [
                    {
                        "title": h.rule.title,
                        "match": h.match,
                        "status": h.rule.status,
                        "level": h.rule.level,
                        "techniques": ", ".join(h.rule.techniques),
                        "usable": "yes" if h.rule.usable else "NO (can never fire)",
                        "fields missing from events": ", ".join(h.rule.unmapped_fields),
                    }
                    for h in hits
                ],
            )
            choice = st.selectbox("Rule", range(len(hits)), format_func=lambda i: hits[i].rule.title)
            rule = hits[choice].rule
            with st.expander("Rule details (SigmaHQ text is untrusted input)"):
                st.markdown(f"`{rule.path}` · id `{rule.id}`")
                st.markdown(md(rule.description))
                if rule.falsepositives:
                    st.markdown("**Documented false positives:** " + md("; ".join(rule.falsepositives)))
                st.code(rule.rule_yaml, language="yaml")
            st.button(
                "Test this rule →",
                type="primary",
                on_click=open_rule,
                args=(rule.rule_yaml, f"SigmaHQ: {rule.title}", rule.techniques),
            )

    with st.expander("Or start from a sample rule (works without the SigmaHQ index)"):
        fixtures = sorted((get_settings().data_dir / "fixtures" / "rules").glob("*.yml"))
        if fixtures:
            c1, c2 = st.columns([3, 1])
            path = c1.selectbox("Fixture rule", fixtures, format_func=lambda p: p.name)
            text = path.read_text(encoding="utf-8")
            c2.button(
                "Use fixture",
                on_click=open_rule,
                args=(
                    text,
                    f"fixture: {path.name}",
                    techniques_from_tags(yaml.safe_load(text).get("tags", [])),
                ),
            )


# ---- ② test ----------------------------------------------------------------------------------


def test_step(events: list[Event]) -> None:
    rule_yaml = st.session_state.get("before_yaml")
    if not rule_yaml:
        st.info("Pick a rule first (step ①).")
        return
    st.caption(
        "The rule is replayed on attacks, their mutations (the five evasion types of Uetz et al.) and "
        "benign look-alikes. Use the sidebar to choose the test data."
    )
    validation_view(rule_yaml)
    with st.expander("Rule YAML"):
        st.code(rule_yaml, language="yaml")
    card = run(rule_yaml, events)
    scorecard_view(card, events)
    if card.valid and card.misses:
        st.button(
            "Harden it →", type="primary", on_click=st.session_state.update, kwargs={"rules_step": "harden"}
        )
    export_view(rule_yaml, "rule")


def scorecard_view(card: Scorecard, events: list[Event]) -> None:
    if not card.valid:
        st.error(f"Rule could not be evaluated: {md(card.error)}")
        return
    attacks = card.hits + card.misses
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Attacks detected", f"{card.hits}/{attacks}")
    c2.metric("Evasion resistance (mutations)", pct(evasion_resistance(card)))
    c3.metric("False alarms", card.false_alarms)
    c4.metric("Benign events", sum(b.benign for b in card.per_transform.values()))
    st.markdown("**Per evasion type**")
    table(
        [
            {
                "transform": t,
                "attacks": b.attacks,
                "detected": b.hits,
                "resistance": pct(b.hits / b.attacks) if b.attacks else "n/a",
                "benign": b.benign,
                "false alarms": b.false_alarms,
            }
            for t, b in card.per_transform.items()
            if b.attacks or b.benign
        ],
    )
    matched = set(card.matched_event_ids)
    st.markdown("**Events**")
    if st.toggle("Only missed attacks and false alarms", key="only_problems"):
        events = [e for e in events if (e.event_id in matched) == (e.label == "benign")]
        if not events:
            st.success("Nothing missed and no false alarms on these events.")
    table(
        [
            {
                "event": e.event_id,
                "label": e.label,
                "transform": e.transform,
                "split": e.split,
                "fired": e.event_id in matched,
                "outcome": outcome(e, e.event_id in matched),
                "command_line": e.command_line,
            }
            for e in events
        ],
    )


def outcome(event: Event, fired: bool) -> str:
    if event.label == "attack":
        return "detected" if fired else "MISSED"
    return "FALSE ALARM" if fired else "ok"


def validation_view(rule_yaml: str) -> None:
    result = validate_rule(rule_yaml)
    for error in result.errors:
        st.error(md(error))
    for warning in result.warnings:
        st.warning(md(warning))
    if result.valid and not result.warnings:
        st.success("Valid Sigma rule, in scope, evaluable by the harness.")


# ---- ③ harden ---------------------------------------------------------------------------------


def harden_step(events: list[Event], all_events: list[Event], index: ReferenceIndex | None) -> None:
    before = st.session_state.get("before_yaml")
    if not before:
        st.info("Pick a rule first (step ①).")
        return
    agent_panel(before, all_events, index)
    st.caption("Or edit the candidate on the right: every edit is re-tested on the same events.")
    left, right = st.columns(2)
    left.markdown("**Before (as-is)**")
    left.code(before, language="yaml")
    right.markdown("**After (hardened candidate)**")
    after = right.text_area("after", key="after_editor", height=420, label_visibility="collapsed")
    right.button("Reset to before", on_click=lambda: st.session_state.update(after_editor=before))

    validation_view(after)
    report = compare(before, after, events)
    if not report.valid:
        st.error(md(report.after.error or report.before.error))
        return

    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Evasion resistance",
        pct(report.evasion_resistance_after),
        delta=None if report.evasion_resistance_delta is None else f"{report.evasion_resistance_delta:+.0%}",
    )
    c2.metric("Attacks detected", f"{report.after.hits}", delta=report.after.hits - report.before.hits)
    c3.metric(
        "False alarms",
        report.false_alarms_after,
        delta=report.false_alarms_after - report.false_alarms_before,
        delta_color="inverse",
    )
    table(
        [
            {
                "transform": t,
                "attacks": d.attacks,
                "before": pct(d.resistance_before),
                "after": pct(d.resistance_after),
                "false alarms before": d.false_alarms_before,
                "false alarms after": d.false_alarms_after,
            }
            for t, d in report.per_transform.items()
            if t in TRANSFORMS and (d.attacks or d.benign)
        ],
    )
    by_id = {e.event_id: e for e in events}
    for title, ids, kind in [
        ("Newly detected attacks", report.newly_detected_event_ids, st.success),
        ("Attacks LOST (regression)", report.lost_event_ids, st.error),
        ("New false alarms", report.new_false_alarm_event_ids, st.error),
        ("False alarms removed", report.removed_false_alarm_event_ids, st.success),
    ]:
        if ids:
            kind(f"**{title}:** " + ", ".join(f"`{i}` ({by_id[i].transform})" for i in ids))
    export_view(after, "candidate")
