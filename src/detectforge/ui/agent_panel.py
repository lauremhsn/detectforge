"""The "Ask the agent" button in the Harden tab.

Off unless DETECTFORGE_UI_ALLOW_AGENT_RUNS=true and an LLM key are set: a public deployment must
not let anyone spend the model quota. The agent gets the selected technique's events and, as in
the CLI, the runner gives it only the tuning split.
"""

import streamlit as st

from detectforge.agent.runner import run_hardening, run_writing
from detectforge.config import get_settings
from detectforge.llm import LLMError, OpenAICompatibleClient
from detectforge.reference.index import ReferenceIndex
from detectforge.schemas import Event
from detectforge.tracing import make_tracer
from detectforge.ui.navigation import go_button


def agent_panel(before_yaml: str, events: list[Event], index: ReferenceIndex | None) -> None:
    """Must run before the "after" editor is created, because it may fill that editor."""
    settings = get_settings()
    technique = st.session_state.get("bench_technique", "(all)")
    blocked = _blocked_reason(settings, technique, events)
    label = "Ask the agent to harden this rule"
    st.caption(
        f"Costs up to {settings.max_model_calls} model calls (usually about 8) of the provider's "
        f"{settings.daily_request_limit} a day, and takes 2 to 6 minutes on the free tier. It only sees the "
        "tuning variations; the result waits for a reviewer."
    )
    if blocked:
        st.button(label, disabled=True, help=blocked)
        st.caption(f"⏳ Agent runs here: {blocked}")
    elif st.button(label, type="primary"):
        with st.spinner("The agent is working: testing revisions on the tuning events (1-2 minutes)…"):
            try:
                outcome = run_hardening(
                    before_yaml,
                    technique,
                    events,
                    OpenAICompatibleClient.from_settings(settings),
                    settings.model,
                    index,
                    settings.runs_dir,
                    make_tracer(settings),
                )
            except (LLMError, ValueError) as e:
                st.error(f"The agent could not run: {e}")
                return
        st.session_state["after_editor"] = outcome.run.final_rule_yaml
        st.session_state["last_agent_run"] = (outcome.run.trace_id, outcome.run.status)
        st.rerun()

    if last := st.session_state.get("last_agent_run"):
        trace_id, status = last
        st.success(
            f"The agent's proposal ({status.replace('_', ' ')}) is in the editor below, and waiting in "
            f"the review queue (run {trace_id[:8]})."
        )
        go_button("review", "Open the review queue →")


def write_panel(technique: str, events: list[Event], index: ReferenceIndex | None) -> None:
    """No usable community rule: ask the agent to write one (same switch and checks as hardening)."""
    settings = get_settings()
    blocked = _blocked_reason(settings, technique, events)
    label = f"Ask the agent to write a rule for {technique}"
    st.caption(
        f"Costs up to {settings.write_max_model_calls} model calls of the provider's "
        f"{settings.daily_request_limit} a day, about 2 minutes; the rule waits for a reviewer."
    )
    if blocked:
        st.button(label, disabled=True, help=blocked, key=f"write_{technique}")
        st.caption(
            f"⏳ Agent runs here: {blocked}. From the command line: "
            f"`detectforge write --technique {technique} --events …`"
        )
        return
    if st.button(label, type="primary", key=f"write_{technique}"):
        with st.spinner("The agent is writing and testing a rule on the tuning events (1-2 minutes)…"):
            try:
                outcome = run_writing(
                    technique,
                    events,
                    OpenAICompatibleClient.from_settings(settings),
                    settings.model,
                    index,
                    settings.runs_dir,
                    make_tracer(settings),
                )
            except (LLMError, ValueError) as e:
                st.error(f"The agent could not run: {e}")
                return
        st.success(
            f"The agent's rule ({outcome.run.status.replace('_', ' ')}) is waiting in the review queue "
            f"(run {outcome.run.trace_id[:8]})."
        )
        go_button("review", "Open the review queue →")


def _blocked_reason(settings, technique: str, events: list[Event]) -> str | None:
    if not settings.ui_allow_agent_runs:
        return "pending (switched off; set DETECTFORGE_UI_ALLOW_AGENT_RUNS=true in .env to enable locally)"
    key = settings.llm_api_key
    if key is None or not key.get_secret_value().strip():
        return "no LLM key (set OPENROUTER_API_KEY in .env)"
    if technique == "(all)":
        return "open a rule first, so its technique is known (or pick one in Lab → Test bench)"
    if not any(e.technique == technique and e.split == "tune" and e.label == "attack" for e in events):
        return f"no tuning attack events for {technique} in this events file"
    return None
