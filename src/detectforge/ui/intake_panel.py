"""The request box at the top of the Find tab: plain words in, ATT&CK techniques out.

Uses the model only where agent runs are allowed (same switch and key as "Ask the agent", since it
spends the same quota); otherwise it uses the keyword fallback and says so.
"""

import streamlit as st

from detectforge.config import get_settings
from detectforge.intake import IntakeResult, interpret_request
from detectforge.llm import LLMError, OpenAICompatibleClient
from detectforge.reference.index import ReferenceIndex
from detectforge.ui.components import md


def intake_panel(index: ReferenceIndex) -> IntakeResult | None:
    """The request box. Returns the interpreted request (techniques, or a clarifying question)."""
    request = st.text_area(
        "What do you want to detect?",
        placeholder="Scheduled-task persistence, or paste a short threat report",
        key="intake_request",
        height=110,
    )
    if st.button("Check coverage", type="primary", disabled=not request.strip()):
        with st.spinner("Interpreting the request…"):
            st.session_state["intake_result"] = interpret_request(request, index, _client()).model_dump()

    if data := st.session_state.get("intake_result"):
        result = IntakeResult.model_validate(data)
        _show(result)
        return result
    return None


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
        st.caption(f"Used {how}: {md(result.note)}")
    if result.status == "needs_clarification":
        st.warning(md(result.clarification or "Please describe the attacker behaviour to cover."))
        return
    if result.rationale:
        st.caption(f"Interpreted by {how}. {md(result.rationale)}")
    if result.rejected:
        st.caption("Ignored (not in the SigmaHQ index): " + md(", ".join(result.rejected)))
