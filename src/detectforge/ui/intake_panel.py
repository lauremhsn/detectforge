"""The request box at the top of the Find tab: plain words in, ATT&CK techniques out.

Uses the model only where agent runs are allowed (same switch and key as "Ask the agent", since it
spends the same quota); otherwise it uses the keyword fallback and says so.
"""

import streamlit as st

from detectforge.config import get_settings
from detectforge.intake import IntakeResult, interpret_request
from detectforge.llm import LLMError, OpenAICompatibleClient
from detectforge.reference.index import ReferenceIndex


def intake_panel(index: ReferenceIndex) -> None:
    """Must run before the technique search box is created, because it may fill that box."""
    request = st.text_input(
        "What do you want to detect?",
        placeholder="e.g. scheduled-task persistence, or paste a short threat report",
        key="intake_request",
    )
    if st.button("Find techniques", disabled=not request.strip()):
        with st.spinner("Interpreting the request…"):
            st.session_state["intake_result"] = interpret_request(request, index, _client()).model_dump()

    if data := st.session_state.get("intake_result"):
        _show(IntakeResult.model_validate(data))


def _client() -> OpenAICompatibleClient | None:
    settings = get_settings()
    if not settings.ui_allow_agent_runs:
        return None
    try:
        return OpenAICompatibleClient.from_settings(settings)
    except LLMError:
        return None


def _show(result: IntakeResult) -> None:
    how = "the model" if result.source == "model" else "keyword search of SigmaHQ"
    if result.note:
        st.caption(f"Used {how}: {result.note}")
    if result.status == "needs_clarification":
        st.warning(result.clarification or "Please describe the attacker behaviour to cover.")
        return
    if result.rationale:
        st.caption(f"Interpreted by {how}. {result.rationale}")
    if result.rejected:
        st.caption("Ignored (not in the SigmaHQ index): " + ", ".join(result.rejected))
    for match in result.techniques:
        c1, c2 = st.columns([1, 4])
        c1.button(
            f"Use {match.technique}",
            key=f"use_{match.technique}",
            on_click=st.session_state.update,
            kwargs={"find_technique": match.technique},
        )
        c2.markdown(
            f"**{match.technique}** · {match.rule_count} rules, e.g. " + "; ".join(match.example_rules)
        )
