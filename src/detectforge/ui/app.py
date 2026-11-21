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
from detectforge.events import EventFileError, load_events
from detectforge.reference import sigmahq
from detectforge.reference.index import ReferenceIndex
from detectforge.review import latest_prompt_versions, list_runs
from detectforge.schemas import Event
from detectforge.ui.components import apply_style
from detectforge.ui.coverage_page import coverage_page
from detectforge.ui.navigation import menu
from detectforge.ui.operations_page import operations_page
from detectforge.ui.request_page import request_page
from detectforge.ui.review_tab import review_tab
from detectforge.ui.rules_page import rules_page

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
CUSTOM = "Custom file"


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


@st.cache_data
def load_events_cached(path: str, mtime: float) -> list[Event]:
    return load_events(path)


def event_sources(data_dir: Path) -> dict[str, list[Path]]:
    """Named event sets: the evaluation set (every data/eval file together) first, when present."""
    sources = {}
    if evaluation := sorted((data_dir / "eval").glob("*.jsonl")):
        sources["Evaluation set"] = evaluation
    if (fixtures := data_dir / "fixtures" / "events.jsonl").exists():
        sources["Fixtures (synthetic)"] = [fixtures]
    return sources


def test_data_sidebar() -> tuple[list[Event], list[Event]]:
    """Which events rules are tested on. Returns (all loaded events, those in the technique/split scope).

    In the sidebar (collapsed by default) because it's a lab setting, but drawn on every page: a widget
    that isn't drawn loses its value, and the Rules area depends on it.
    """
    st.sidebar.markdown("**Test data**")
    st.sidebar.caption("Which events rules are tested on (a lab setting).")
    box = st.sidebar.container()
    data_dir = get_settings().data_dir
    events: list[Event] = []
    sources = event_sources(data_dir)
    source = box.selectbox("Events", [*sources, CUSTOM], key="events_source")
    if source == CUSTOM:
        st.session_state.setdefault("events_path", str(data_dir / "fixtures" / "events.jsonl"))
        paths = [Path(box.text_input("Events file (JSONL)", key="events_path"))]
    else:
        paths = sources[source]
    try:
        for path in paths:
            events += load_events_cached(str(path), path.stat().st_mtime)
    except (OSError, EventFileError) as e:
        box.error(f"Cannot load events: {e}")
        events = []

    techniques = sorted({e.technique for e in events})
    st.session_state["available_techniques"] = techniques
    technique = box.selectbox("Technique", ["(all)", *techniques], key="technique_filter")
    split = box.radio("Split", ["(all)", "tune", "heldout"], horizontal=True)
    filtered = [
        e
        for e in events
        if (technique == "(all)" or e.technique == technique) and (split == "(all)" or e.split == split)
    ]
    attacks = sum(e.label == "attack" for e in filtered)
    box.caption(f"{len(filtered)} events in scope: {attacks} attack, {len(filtered) - attacks} benign")
    st.sidebar.caption(
        f"Testing on: {source if source != CUSTOM else 'custom file'} · "
        f"{'all techniques' if technique == '(all)' else technique} · {attacks} attacks, "
        f"{len(filtered) - attacks} benign"
    )
    return events, filtered


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
    all_events, events = test_data_sidebar()

    index = load_index(str(settings.data_dir / "sigmahq"), settings.ui_auto_fetch_index)
    loaded = index if isinstance(index, ReferenceIndex) else None
    if page == "coverage":
        rule_texts = {r.id: r.rule_yaml for r in loaded.rules} if loaded else {}
        coverage_page(settings.data_dir, settings.runs_dir, rule_texts, pending)
    elif page == "request":
        request_page(index, all_events)
    elif page == "rules":
        rules_page(events, all_events, index)
    elif page == "review":
        review_tab(settings.runs_dir)
    else:
        operations_page(settings.runs_dir, settings.data_dir)
        about()


main()
