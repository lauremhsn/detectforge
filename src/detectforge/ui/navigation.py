"""Where everything is: the areas of the app, the question each one answers, and how to jump.

Product areas, organised around what people come to do:
- Home: what DetectForge is, for whom, and where to start
- Posture: a SOC lead's "where are we weak, and can we prove it?"
- Threats: a detection engineer's "a new threat came in: are we covered?"
- Rules: "test a rule against attacker variations, see exactly what it catches, then harden it"
- Review: an approver's "what's waiting for me, and is it safe to ship?"
- Reports: "give me something to send my manager (or my engineers)"
Then, set apart: the Lab (how the system itself is evaluated: arms, agent metrics, prompt versions,
test-bench settings) and Settings (team, reviewer keys, what the workspace contains).

Product areas speak plainly ("variations the agent never saw"); evaluation vocabulary (tuning,
held-out, prompt versions, setup hashes) lives in the Lab and in each review's audit trail. Each area
has its own URL (?page=review), so a link can be shared.
"""

from dataclasses import dataclass

import streamlit as st


@dataclass(frozen=True)
class Section:
    key: str
    title: str
    question: str


SECTIONS = [
    Section("home", "Home", "What DetectForge does, and where to start"),
    Section("coverage", "Posture", "Where are we weak, and can we prove it?"),
    Section("request", "Threats", "A new threat came in: are we covered?"),
    Section("rules", "Rules", "Test a rule against attacker variations, then harden it"),
    Section("review", "Review", "What's waiting for a decision, and is it safe to ship?"),
    Section("reports", "Reports", "A summary to share with a manager or an engineer"),
    Section("operations", "Lab", "How the agent is evaluated, what it costs, and where it fails"),
    Section("settings", "Settings", "Team, reviewer keys, and what this workspace contains"),
]
BY_KEY = {s.key: s for s in SECTIONS}
PAGE = "page"  # session key of the current area


def go(key: str) -> None:
    """Button callback: switch area (runs before widgets are drawn, so the menu follows)."""
    st.session_state[PAGE] = key


def open_rule(rule_yaml: str, label: str, techniques: list[str], step: str = "test") -> None:
    """Button callback: make this the rule under test, test it on its technique, open the Rules area."""
    st.session_state.update(before_yaml=rule_yaml, after_editor=rule_yaml, rule_label=label)
    available = st.session_state.get("available_techniques", [])
    if match := next((t for t in techniques if t in available), None):
        st.session_state["bench_technique"] = match
    st.session_state["rules_step"] = step
    go("rules")


def go_button(key: str, label: str | None = None, primary: bool = False, where=st) -> None:
    section = BY_KEY[key]
    where.button(
        label or f"{section.title} →",
        key=f"go_{key}_{label or ''}",
        type="primary" if primary else "secondary",
        on_click=go,
        args=(key,),
    )


def menu(pending: int) -> str:
    """The top bar: product name and the areas. Returns the current area key.

    The page also lives in the URL (?page=...): opening a shared link lands on that area, and moving
    between areas updates the address bar.
    """
    if PAGE not in st.session_state:
        wanted = st.query_params.get(PAGE)
        st.session_state[PAGE] = wanted if wanted in BY_KEY else "home"
    if st.session_state[PAGE] == "home":  # the landing page stands on its own, without the app's tabs
        if st.query_params.get(PAGE) != "home":
            st.query_params[PAGE] = "home"
        return "home"

    def label(key: str) -> str:
        badge = f"  ({pending})" if key == "review" and pending else ""
        return f"{BY_KEY[key].title}{badge}"

    with st.container(key="topbar"):
        brand, nav = st.columns([1, 5], vertical_alignment="center")
        brand.button(
            "🛡️ DetectForge", key="brand", on_click=go, args=("home",), type="tertiary",
            help="Back to the product page",
        )  # fmt: skip
        page = nav.radio(
            "Areas",
            [s.key for s in SECTIONS if s.key != "home"],
            format_func=label,
            key=PAGE,
            horizontal=True,
            label_visibility="collapsed",
        )
    if st.query_params.get(PAGE) != page:
        st.query_params[PAGE] = page
    return page


def header(key: str, purpose: str) -> None:
    """Every area opens with its name and what it's for, in one line, so nobody has to guess."""
    st.title(BY_KEY[key].title)
    st.caption(purpose)
