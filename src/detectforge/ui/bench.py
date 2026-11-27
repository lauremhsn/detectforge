"""The test bench: which events rules are replayed on.

A product user never needs to choose: rules are tested on the full attack library (every attack, its
evasion variations, and the legitimate look-alikes) for the rule's own technique, which the Rules area
sets when a rule is opened. Researchers can narrow it (one technique, only the tuning or only the
held-out variations, another event file) in the Lab. The choice is kept in plain session keys, not in
widgets, so it survives moving between areas.
"""

from pathlib import Path

import streamlit as st

from detectforge.config import get_settings
from detectforge.events import EventFileError, load_events
from detectforge.schemas import Event

LIBRARY = "Attack library (evaluation set)"
FIXTURES = "Small sample (fixtures)"
ALL = "(all)"
SPLITS = {
    ALL: "every variation",
    "tune": "only variations the agent may see",
    "heldout": "only unseen variations",
}


@st.cache_data
def _load(path: str, mtime: float) -> list[Event]:
    return load_events(path)


def sources(data_dir: Path) -> dict[str, list[Path]]:
    found = {}
    if evaluation := sorted((data_dir / "eval").glob("*.jsonl")):
        found[LIBRARY] = evaluation
    if (fixtures := data_dir / "fixtures" / "events.jsonl").exists():
        found[FIXTURES] = [fixtures]
    return found


def bench_events() -> tuple[list[Event], list[Event]]:
    """(every loaded event, the events in the bench's scope)."""
    found = sources(get_settings().data_dir)
    source = st.session_state.get("bench_source")
    if source not in found:
        source = next(iter(found), None)
        st.session_state["bench_source"] = source
    events: list[Event] = []
    try:
        for path in found.get(source, []):
            events += _load(str(path), path.stat().st_mtime)
    except (OSError, EventFileError) as e:
        st.error(f"Cannot load the test events: {e}")
        events = []
    st.session_state["available_techniques"] = sorted({e.technique for e in events})
    technique = st.session_state.get("bench_technique", ALL)
    split = st.session_state.get("bench_split", ALL)
    scoped = [
        e
        for e in events
        if (technique == ALL or e.technique == technique) and (split == ALL or e.split == split)
    ]
    return events, scoped


def describe() -> str:
    """The current scope in one phrase, for the Rules area."""
    technique = st.session_state.get("bench_technique", ALL)
    split = st.session_state.get("bench_split", ALL)
    where = "every technique" if technique == ALL else technique
    return f"{where} · {SPLITS.get(split, split)}"


def bench_settings() -> None:
    """The Lab's controls. Widgets write through to the plain session keys the product pages read."""
    found = sources(get_settings().data_dir)

    def keep(widget: str, key: str) -> None:
        st.session_state[key] = st.session_state[widget]

    names = list(found)
    current = st.session_state.get("bench_source")
    st.selectbox(
        "Events",
        names,
        index=names.index(current) if current in names else 0,
        key="w_bench_source",
        on_change=keep,
        args=("w_bench_source", "bench_source"),
        help="The attack library is the evaluation set: base attacks, their variations, and legitimate "
        "look-alike commands. The sample is a tiny synthetic set for trying the app without data.",
    )
    techniques = [ALL, *st.session_state.get("available_techniques", [])]
    tech = st.session_state.get("bench_technique", ALL)
    st.selectbox(
        "Technique",
        techniques,
        index=techniques.index(tech) if tech in techniques else 0,
        key="w_bench_technique",
        on_change=keep,
        args=("w_bench_technique", "bench_technique"),
        help="Opening a rule sets this to the rule's technique, so it's scored on its own attacks.",
    )
    splits = list(SPLITS)
    split = st.session_state.get("bench_split", ALL)
    st.radio(
        "Variations",
        splits,
        index=splits.index(split) if split in splits else 0,
        format_func=SPLITS.get,
        key="w_bench_split",
        on_change=keep,
        args=("w_bench_split", "bench_split"),
        horizontal=True,
        help="The agent may only ever see the tuning variations; unseen (held-out) ones are how it is "
        "judged. A product user always sees every variation.",
    )
