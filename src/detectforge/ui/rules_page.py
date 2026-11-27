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
from detectforge.review import list_runs, load_run
from detectforge.rules.validate import validate_rule
from detectforge.schemas import TRANSFORMS, Event, Scorecard
from detectforge.ui import techniques as tx
from detectforge.ui.agent_panel import agent_panel
from detectforge.ui.bench import describe
from detectforge.ui.components import export_view, md, pct, table
from detectforge.ui.navigation import go, header, open_rule
from detectforge.ui.testbench import grid

STEPS = {
    "pick": "① Pick a rule",
    "test": "② Test it against evasions",
    "harden": "③ Harden it",
}


def rules_page(events: list[Event], all_events: list[Event], index: ReferenceIndex | str) -> None:
    header("rules", "Measure one rule against attacker variations, then make it harder to evade.")
    st.session_state.setdefault("rules_step", "pick")
    with st.container(key="stepper"):
        step = st.radio(
            "Step",
            list(STEPS),
            format_func=STEPS.get,
            horizontal=True,
            key="rules_step",
            label_visibility="collapsed",
        )
    if label := st.session_state.get("rule_label"):
        st.info(f"**Rule under test:** {md(label)} · tested on {describe()}")
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
        options = list(tx.TECHNIQUES)
        technique = c1.selectbox(
            "Attacker technique", options, format_func=tx.label, key="find_technique",
            help="What the attacker does. The ATT&CK id is in brackets for experts.",
        )  # fmt: skip
        query = c2.text_input("Keywords (optional)", "", placeholder="e.g. schtasks create")
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
                "No usable community rule here. DetectForge would write a new one: use **Threats** "
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

    with st.expander("Import your own rules (Sigma YAML)"):
        st.caption(
            "Already have rules in your SIEM? Export them as Sigma (most SIEM vendors and sigma-cli can) "
            "and drop the files here: each is validated and can be tested like a community rule. Rules in "
            "a SIEM's own query language (SPL, KQL) aren't supported."
        )
        uploads = st.file_uploader("Sigma rule files", type=["yml", "yaml"], accept_multiple_files=True)
        for i, upload in enumerate(uploads or []):
            text = upload.getvalue().decode("utf-8", errors="replace")
            check = validate_rule(text)
            try:
                tags = (yaml.safe_load(text) or {}).get("tags", []) or []
            except yaml.YAMLError:
                tags = []
            c1, c2 = st.columns([3, 1], vertical_alignment="center")
            state = "valid" if check.valid else f"not valid: {'; '.join(check.errors)[:160]}"
            c1.markdown(f"**{md(upload.name)}** · {md(state)}")
            c2.button(
                "Test it →", key=f"import_{i}_{upload.name}", disabled=not check.valid,
                on_click=open_rule, args=(text, f"imported: {upload.name}", techniques_from_tags(tags)),
            )  # fmt: skip

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
        "The rule is replayed on attacks, their variations (the five evasion types of Uetz et al.) and "
        "legitimate look-alike commands."
    )
    validation_view(rule_yaml)
    card = run(rule_yaml, events)
    scorecard_view(card, events, rule_yaml)
    if card.valid and card.misses:
        st.button(
            "Harden it →", type="primary", on_click=st.session_state.update, kwargs={"rules_step": "harden"}
        )
    with st.expander("Rule YAML"):
        st.code(rule_yaml, language="yaml")
    export_view(rule_yaml, "rule")


def summary_line(card: Scorecard) -> str:
    """The test result in one sentence, before any table."""
    attacks = card.hits + card.misses
    if not attacks:
        return "No attacks in the test data for this rule, so nothing to measure yet."
    evaded = [t for t, b in card.per_transform.items() if t != "none" and b.misses]
    parts = [f"**Catches {card.hits} of {attacks} attacks and variations.**"]
    parts.append(f"Evaded by {', '.join(evaded)}." if evaded else "No variation slips past.")
    if card.false_alarms:
        parts.append(f"{card.false_alarms} false alarm(s) on legitimate commands.")
    return " ".join(parts)


def scorecard_view(card: Scorecard, events: list[Event], rule_yaml: str = "") -> None:
    if not card.valid:
        st.error(f"Rule could not be evaluated: {md(card.error)}")
        return
    attacks = card.hits + card.misses
    (st.success if not card.misses and not card.false_alarms else st.warning)(summary_line(card))
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
    problems = [e for e in events if (e.event_id in matched) == (e.label == "benign")]
    missed = sum(e.label == "attack" for e in problems)
    st.markdown(f"**What slipped past: {missed} missed attack(s), {len(problems) - missed} false alarm(s)**")
    st.caption(
        "Highlighted: the text this rule looks for in the command line. A disguised attack slips past when "
        "the disguise breaks exactly that text (an inserted character, a swapped flag, a shortened name)."
    )
    if problems:
        st.html(grid(problems, {"this rule": (rule_yaml, matched)}))
    else:
        st.success("Nothing missed and no false alarms on these events.")
    with st.expander(f"Every event, grouped by attack ({len(events)})"):
        st.html(grid(events, {"this rule": (rule_yaml, matched)}))


def validation_view(rule_yaml: str) -> None:
    result = validate_rule(rule_yaml)
    for error in result.errors:
        st.error(md(error))
    for warning in result.warnings:
        st.warning(md(warning))
    if result.valid and not result.warnings:
        st.success("Valid Sigma rule, in scope, evaluable by the harness.")


# ---- ③ harden ---------------------------------------------------------------------------------


def _existing_proposals(rule_yaml: str) -> None:
    """Say so when the agent already worked on this exact rule, instead of spending calls again."""
    runs_dir = get_settings().runs_dir
    target = " ".join(rule_yaml.split())
    found = [
        s
        for s in list_runs(runs_dir)
        if s.mode == "harden"
        and " ".join(load_run(runs_dir, s.trace_id).run.original_rule_yaml.split()) == target
    ]
    if not found:
        return
    approved = sum(s.decision is not None and s.decision.decision == "approved" for s in found)
    waiting = sum(s.decision is None for s in found)
    left, right = st.columns([4, 1], vertical_alignment="center")
    left.info(
        f"The agent already hardened this rule {len(found)} time(s): {approved} approved, {waiting} waiting "
        "for a reviewer. Look at those first; asking again spends model calls."
    )
    right.button("Open Review →", key="existing_review", on_click=go, args=("review",))


def harden_step(events: list[Event], all_events: list[Event], index: ReferenceIndex | None) -> None:
    before = st.session_state.get("before_yaml")
    if not before:
        st.info("Pick a rule first (step ①).")
        return
    _existing_proposals(before)
    with st.container(border=True):
        st.markdown("**Let the agent harden it**")
        st.caption(
            "The agent sees only the tuning variations; its proposal goes to Review with the evidence, "
            "never straight to deployment."
        )
        agent_panel(before, all_events, index)
    st.markdown("**Or edit it yourself**")
    st.caption("Every edit of the candidate on the right is re-tested on the same events.")
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
    st.markdown("**Side by side on the same events**")
    changed = st.toggle("Only events where the two versions differ", value=True, key="compare_changed")
    st.html(
        grid(
            events,
            {
                "before": (before, set(report.before.matched_event_ids)),
                "after": (after, set(report.after.matched_event_ids)),
            },
            changed_only=changed,
        )
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
