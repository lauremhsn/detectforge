"""New request: "a new threat came in, are we covered?" answered per technique, with the next step.

The request (or a pasted threat report) is mapped to ATT&CK techniques. For each one, code (not the
model) checks the best usable community rule against the attacks and their variations in the test
data, and gives a verdict: robust, evadable, not covered, or not measurable yet. Each verdict comes
with its action: test or harden the rule, or have the agent write one.
"""

from typing import Literal

import streamlit as st
from pydantic import BaseModel

from detectforge.agent.runner import find_usable_rule, scope_events
from detectforge.harness import run
from detectforge.harness.compare import evasion_resistance
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event
from detectforge.ui.agent_panel import write_panel
from detectforge.ui.components import md, pct
from detectforge.ui.intake_panel import intake_panel
from detectforge.ui.navigation import header, open_rule

Verdict = Literal["robust", "evadable", "not_covered", "untested"]


class Coverage(BaseModel):
    technique: str
    verdict: Verdict
    rule_id: str | None = None
    rule_title: str | None = None
    rule_yaml: str | None = None
    resistance: float | None = None
    detected: int = 0
    attacks: int = 0
    false_alarms: int = 0
    evaded_by: list[str] = []


def assess(technique: str, index: ReferenceIndex, events: list[Event]) -> Coverage:
    """The coverage verdict for one technique: deterministic, from the harness."""
    rule = find_usable_rule(index, technique)
    if rule is None:
        return Coverage(technique=technique, verdict="not_covered")
    base = Coverage(
        technique=technique,
        verdict="untested",
        rule_id=rule.id,
        rule_title=rule.title,
        rule_yaml=rule.rule_yaml,
    )
    scoped = scope_events(events, technique)
    if not any(e.label == "attack" for e in scoped):
        return base
    card = run(rule.rule_yaml, scoped)
    resistance = evasion_resistance(card)
    evaded = [t for t, b in card.per_transform.items() if t != "none" and b.misses]
    robust = card.misses == 0 and card.false_alarms == 0
    return base.model_copy(
        update={
            "verdict": "robust" if robust else "evadable",
            "resistance": resistance,
            "detected": card.hits,
            "attacks": card.hits + card.misses,
            "false_alarms": card.false_alarms,
            "evaded_by": evaded,
        }
    )


def request_page(index: ReferenceIndex | str, all_events: list[Event]) -> None:
    header(
        "request",
        "Describe what you want to detect, or paste a threat report. DetectForge finds the techniques it "
        "involves and checks, for each one, whether your rules still catch the attack when an attacker "
        "varies the command line.",
    )
    if isinstance(index, str):
        st.info(index)
        return
    result = intake_panel(index)
    if result is None or result.status != "mapped":
        with st.expander("Try an example"):
            st.markdown(
                "- *detect scheduled-task persistence*\n"
                "- *attackers deleting shadow copies before ransomware*\n"
                "- *registry run keys used for persistence*"
            )
        return
    st.divider()
    for match in result.techniques:
        _verdict_card(assess(match.technique, index, all_events), all_events, index)


def _verdict_card(c: Coverage, events: list[Event], index: ReferenceIndex) -> None:
    with st.container(border=True):
        if c.verdict == "not_covered":
            st.markdown(f"### 🟥 {c.technique} — not covered")
            st.markdown("No usable community rule exists for this technique. The agent can write one.")
            write_panel(c.technique, events, index)
            return

        title = md(c.rule_title or "")
        if c.verdict == "untested":
            st.markdown(f"### ⬜ {c.technique} — rule found, not measured")
            st.markdown(
                f"Best community rule: **{title}**. There are no attacks for this technique in the "
                "current test data, so its evasion resistance can't be measured yet."
            )
        elif c.verdict == "robust":
            st.markdown(f"### 🟩 {c.technique} — covered")
            st.markdown(f"**{title}** detects all {c.attacks} attacks and variations, with no false alarms.")
        else:
            st.markdown(f"### 🟧 {c.technique} — covered, but evadable")
            what = f"evaded by {', '.join(c.evaded_by)}" if c.evaded_by else "misses some attacks"
            alarms = f", {c.false_alarms} false alarm(s)" if c.false_alarms else ""
            st.markdown(
                f"**{title}** detects {c.detected} of {c.attacks} attacks and variations "
                f"({pct(c.resistance)} of variations); {what}{alarms}."
            )
        c1, c2, _ = st.columns([1, 1, 2])
        label = f"SigmaHQ: {c.rule_title}"
        c1.button(
            "See the evidence →",
            key=f"test_{c.technique}",
            on_click=open_rule,
            args=(c.rule_yaml, label, [c.technique], "test"),
        )
        if c.verdict == "evadable":
            c2.button(
                "Harden it →",
                key=f"harden_{c.technique}",
                type="primary",
                on_click=open_rule,
                args=(c.rule_yaml, label, [c.technique], "harden"),
            )
