"""Where everything is: the sections of the app, the question each one answers, and how to jump.

Organised around what people come to do, not around pipeline steps:
- Coverage: a SOC lead's "where are we weak, and can we prove it?"
- New request: a detection engineer's "a new threat came in: are we covered?"
- Rules: "test and harden one rule"
- Review queue: a reviewer's "what's waiting for me, and is it safe to ship?"
- Agent operations: "what does the agent cost, and is it failing?"
"""

from dataclasses import dataclass

import streamlit as st


@dataclass(frozen=True)
class Section:
    key: str
    icon: str
    title: str
    question: str


SECTIONS = [
    Section("coverage", "🛡️", "Coverage", "Where are we weak, and can we prove it?"),
    Section("request", "📨", "New request", "A new threat came in: are we covered?"),
    Section("rules", "🧪", "Rules", "Test one rule against evasions, then harden it"),
    Section("review", "✅", "Review queue", "Approve or reject what the agent proposed"),
    Section("operations", "⚙️", "Agent operations", "Runs, model calls, failures"),
]
BY_KEY = {s.key: s for s in SECTIONS}
PAGE = "page"  # session key of the current section


def go(key: str) -> None:
    """Button callback: switch section (runs before widgets are drawn, so the menu follows)."""
    st.session_state[PAGE] = key


def open_rule(rule_yaml: str, label: str, techniques: list[str], step: str = "test") -> None:
    """Button callback: make this the rule under test, scope the events to it, open the Rules section."""
    st.session_state.update(before_yaml=rule_yaml, after_editor=rule_yaml, rule_label=label)
    available = st.session_state.get("available_techniques", [])
    if match := next((t for t in techniques if t in available), None):
        st.session_state["technique_filter"] = match
    st.session_state["rules_step"] = step
    go("rules")


def go_button(key: str, label: str | None = None, primary: bool = False, where=st) -> None:
    section = BY_KEY[key]
    where.button(
        label or f"{section.icon} {section.title} →",
        key=f"go_{key}_{label or ''}",
        type="primary" if primary else "secondary",
        on_click=go,
        args=(key,),
    )


def menu(pending: int) -> str:
    """The section menu in the sidebar. Returns the current section key."""
    st.session_state.setdefault(PAGE, "coverage")

    def label(key: str) -> str:
        s = BY_KEY[key]
        badge = f"  ({pending})" if key == "review" and pending else ""
        return f"{s.icon} {s.title}{badge}"

    key = st.sidebar.radio("Go to", [s.key for s in SECTIONS], format_func=label, key=PAGE)
    st.sidebar.caption(BY_KEY[key].question)
    return key


def header(key: str, purpose: str) -> None:
    """Every section opens with what it's for, in one line, so nobody has to guess."""
    s = BY_KEY[key]
    st.title(f"{s.icon} {s.title}")
    st.caption(purpose)
