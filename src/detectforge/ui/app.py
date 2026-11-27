"""DetectForge UI: are our detection rules really covering us, and can we prove it?

Run from the repo root:
    uv run --group ui python -m streamlit run src/detectforge/ui/app.py --server.address localhost

Organised around what people come to do (see navigation.py): Posture, Threats, Review and Rules,
plus a Lab for how the system is evaluated. A thin layer over the library: every number on
screen comes from the same functions the CLI and tests use. The UI shows held-out events to the human;
the agent itself only ever receives the tuning split.
"""

import sys
from pathlib import Path

try:
    import detectforge  # noqa: F401
except ModuleNotFoundError:  # a plain checkout without the package installed (Streamlit Cloud)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from detectforge.config import get_settings
from detectforge.reference import sigmahq
from detectforge.reference.index import ReferenceIndex
from detectforge.review import latest_prompt_versions, list_runs
from detectforge.ui.bench import bench_events
from detectforge.ui.components import apply_style
from detectforge.ui.coverage_page import coverage_page
from detectforge.ui.home_page import home_page
from detectforge.ui.navigation import menu
from detectforge.ui.operations_page import operations_page
from detectforge.ui.reports_page import reports_page
from detectforge.ui.request_page import request_page
from detectforge.ui.review_tab import review_tab
from detectforge.ui.rules_page import rules_page
from detectforge.ui.settings_page import settings_page

PIPELINE = [
    ("Request (plain words → techniques)", True),
    ("Find existing rules", True),
    ("Adversarially validate", True),
    ("Harden by hand", True),
    ("Harden with the agent", True),
    ("Re-validate (before/after)", True),
    ("Write new rule (fallback)", True),
    ("Review and approve", True),
    ("Tune false alarms", False),
]


@st.cache_resource(show_spinner="Downloading and indexing SigmaHQ (first launch only, ~20 s)…")
def load_index(index_dir: str, auto_fetch: bool) -> ReferenceIndex | str:
    """The index, or a message explaining why there is none."""
    path = Path(index_dir)
    try:
        return ReferenceIndex.load(path)
    except FileNotFoundError as e:
        if not auto_fetch:
            return str(e)
    try:
        sigmahq.fetch_and_build(path)
        return ReferenceIndex.load(path)
    except (OSError, sigmahq.ReleaseIntegrityError) as e:
        return f"Could not build the SigmaHQ index: {e}"


def about() -> None:
    """What DetectForge is and what's built, shown in the Lab."""
    with st.expander("About DetectForge"):
        st.caption(
            "Finds existing community Sigma rules, measures how they hold up against command-line "
            "evasion (Uetz et al., USENIX Security 2024), hardens them with an LLM agent, and routes "
            "every change to a human. The agent proposes; it never deploys."
        )
        for step, done in PIPELINE:
            st.markdown(f"✅ **{step}**" if done else f"⏳ **{step}** — pending")


def main() -> None:
    st.set_page_config(
        page_title="DetectForge", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed"
    )
    apply_style()
    settings = get_settings()
    runs = list_runs(settings.runs_dir)
    current = latest_prompt_versions(runs)
    pending = sum(r.decision is None and r.prompt_version in current for r in runs)
    page = menu(pending)
    all_events, events = bench_events()

    index = load_index(str(settings.data_dir / "sigmahq"), settings.ui_auto_fetch_index)
    loaded = index if isinstance(index, ReferenceIndex) else None
    rule_texts = {r.id: r.rule_yaml for r in loaded.rules} if loaded else {}
    if page == "home":
        home_page(settings.data_dir, settings.runs_dir, pending)
    elif page == "coverage":
        coverage_page(settings.data_dir, settings.runs_dir, rule_texts, pending)
    elif page == "request":
        request_page(index, all_events)
    elif page == "rules":
        rules_page(events, all_events, index)
    elif page == "review":
        review_tab(settings.runs_dir)
    elif page == "reports":
        reports_page(settings.data_dir, settings.runs_dir, rule_texts)
    elif page == "settings":
        settings_page(settings.data_dir, settings.runs_dir)
    else:
        operations_page(settings.runs_dir, settings.data_dir)
        about()


main()
