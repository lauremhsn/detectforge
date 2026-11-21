"""Threats: "a new threat came in, are we covered?" answered per technique, with the next step.

The request (or a pasted threat report) is mapped to ATT&CK techniques. For each one, code (not the
model) checks the best usable community rule against the attacks and their variations in the test
data, and gives a verdict: robust, evadable, not covered, or not measurable yet. Each verdict comes
with its action: test or harden the rule, or have the agent write one.
"""

from typing import Literal

import streamlit as st
from pydantic import BaseModel

from detectforge.agent.runner import scope_events
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
    usable_rules: int = 0
    detected_together: int = 0  # attacks caught by at least one usable rule


def assess(technique: str, index: ReferenceIndex, events: list[Event]) -> Coverage:
    """The coverage verdict for one technique: deterministic, from the harness.

    Every usable community rule tagged with exactly this technique is replayed on its attacks and
    variations. The verdict names the strongest single rule (most attacks detected, then fewest false
    alarms), which is the one to harden, and also reports what all of them catch together, which is
    the coverage of a team that deploys every one.
    """
    usable = [r for r in index.rules if technique in r.techniques and r.usable]
    if not usable:
        return Coverage(technique=technique, verdict="not_covered")
    scoped = scope_events(events, technique)
    attacks = {e.event_id for e in scoped if e.label == "attack"}
    if not attacks:
        first = usable[0]
        return Coverage(
            technique=technique, verdict="untested", rule_id=first.id, rule_title=first.title,
            rule_yaml=first.rule_yaml, usable_rules=len(usable),
        )  # fmt: skip

    cards = [(rule, run(rule.rule_yaml, scoped)) for rule in usable]
    cards = [(rule, card) for rule, card in cards if card.valid]
    together = set().union(*(set(card.matched_event_ids) & attacks for _, card in cards)) if cards else set()
    if not cards:
        return Coverage(technique=technique, verdict="untested", usable_rules=len(usable))
    rule, card = max(cards, key=lambda rc: (rc[1].hits, -rc[1].false_alarms))
    robust = card.misses == 0 and card.false_alarms == 0
    return Coverage(
        technique=technique,
        verdict="robust" if robust else "evadable",
        rule_id=rule.id,
        rule_title=rule.title,
        rule_yaml=rule.rule_yaml,
        resistance=evasion_resistance(card),
        detected=card.hits,
        attacks=card.hits + card.misses,
        false_alarms=card.false_alarms,
        evaded_by=[t for t, b in card.per_transform.items() if t != "none" and b.misses],
        usable_rules=len(cards),
        detected_together=len(together),
    )


def request_page(index: ReferenceIndex | str, all_events: list[Event]) -> None:
    header(
        "request",
        "Paste a request or a threat report to see whether your rules catch it, including the "
        "variations attackers use.",
    )
    if isinstance(index, str):
        st.info(index)
        return
    with st.container(border=True):
        result = intake_panel(index)
        st.caption("Or try an example:")
        for column, example in zip(st.columns(len(EXAMPLES)), EXAMPLES, strict=True):
            column.button(
                example, key=f"example_{example}", on_click=st.session_state.update,
                kwargs={"intake_request": example}, width="stretch",
            )  # fmt: skip
    if result is None or result.status != "mapped":
        return
    count = len(result.techniques)
    st.markdown(f"#### {count} technique{'s' if count != 1 else ''}")
    verdicts = [assess(match.technique, index, all_events) for match in result.techniques]
    for start in range(0, len(verdicts), 2):
        for column, c in zip(st.columns(2), verdicts[start : start + 2], strict=False):
            with column:
                _verdict_card(c, all_events, index)


EXAMPLES = [
    "detect scheduled-task persistence",
    "attackers deleting shadow copies before ransomware",
    "registry run keys used for persistence",
]
HEADLINE = {
    "not_covered": ("🟥", "not covered"),
    "untested": ("⬜", "rule found, not measured"),
    "robust": ("🟩", "covered"),
    "evadable": ("🟧", "covered, but evadable"),
}


def _verdict_card(c: Coverage, events: list[Event], index: ReferenceIndex) -> None:
    icon, words = HEADLINE[c.verdict]
    with st.container(border=True):
        st.markdown(f"#### {icon} {c.technique} — {words}")
        if c.verdict == "not_covered":
            st.markdown("No usable community rule exists for this technique. The agent can write one.")
            write_panel(c.technique, events, index)
            return

        title = md(c.rule_title or "")
        if c.verdict == "untested":
            st.markdown(
                f"Best community rule: **{title}**. There are no attacks for this technique in the "
                "current test data, so its evasion resistance can't be measured yet."
            )
        else:
            left, right = st.columns([1, 2], vertical_alignment="center")
            left.metric(
                "Caught",
                f"{c.detected}/{c.attacks}",
                help="Attacks and their variations caught by the strongest single community rule, "
                "replayed by the harness (not judged by the model).",
            )
            if c.verdict == "robust":
                right.markdown(f"**{title}** catches every attack and variation, with no false alarms.")
            else:
                what = f"evaded by {', '.join(c.evaded_by)}" if c.evaded_by else "misses some attacks"
                alarms = f"; {c.false_alarms} false alarm(s)" if c.false_alarms else ""
                right.markdown(
                    f"Strongest single rule: **{title}**, {what}{alarms} "
                    f"({pct(c.resistance)} of variations caught)."
                )
        if c.attacks and c.usable_rules > 1:
            st.caption(
                f"Best of {c.usable_rules} usable community rules for {c.technique}. All of them deployed "
                f"together would catch {c.detected_together} of {c.attacks}."
            )
        if not c.rule_yaml:
            return
        c1, c2 = st.columns(2)
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
