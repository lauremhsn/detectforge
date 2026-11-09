"""Minimal DetectForge UI: find an existing rule, validate it adversarially, harden it, compare.

Run from the repo root:  uv run --group ui streamlit run src/detectforge/ui/app.py

Read-only over the library: every number on screen comes from the same functions the CLI and
tests use (search, validate_rule, run, compare). The UI shows held-out events to the human; the
agent never uses this UI.
"""

from pathlib import Path

import streamlit as st
import yaml

from detectforge.config import get_settings
from detectforge.events import EventFileError, load_events
from detectforge.harness import run
from detectforge.harness.compare import compare, evasion_resistance
from detectforge.reference.index import ReferenceIndex, techniques_from_tags
from detectforge.rules.validate import validate_rule
from detectforge.schemas import TRANSFORMS, Event, Scorecard

PIPELINE = [
    ("Find existing rules", "done", "SigmaHQ search"),
    ("Adversarially validate", "done", "harness scorecard"),
    ("Harden", "manual", "edit by hand; agent loop lands W4"),
    ("Re-validate (before/after)", "done", "compare"),
    ("Write new rule (fallback)", "todo", "W6"),
    ("Approve", "todo", "review UI v1, W5"),
    ("Tune false alarms", "todo", "Laure's FP tuning module"),
]
STATUS_ICON = {"done": "✅", "manual": "🟡", "todo": "⏳"}


@st.cache_resource
def load_index(index_dir: str) -> ReferenceIndex | None:
    try:
        return ReferenceIndex.load(Path(index_dir))
    except FileNotFoundError:
        return None


@st.cache_data
def load_events_cached(path: str, mtime: float) -> list[Event]:
    return load_events(path)


def table(rows: list[dict]) -> None:
    """Render rows as a markdown table (st.dataframe needs pandas, which some machines block)."""
    if not rows:
        return
    cols = list(rows[0])
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(_cell(r[c]) for c in cols) + " |" for r in rows]
    st.markdown("\n".join(lines))


def _cell(value: object) -> str:
    # Escape markdown so event command lines and rule titles render literally.
    text = str(value).replace("\n", " ")
    for ch in "\\|*_`[]<>":
        text = text.replace(ch, "\\" + ch)
    return text


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def set_rule_under_test(rule_yaml: str, label: str, techniques: list[str]) -> None:
    """Make this the rule under test and scope the events to its technique when we have them."""
    st.session_state.update(before_yaml=rule_yaml, after_editor=rule_yaml, rule_label=label)
    available = st.session_state.get("available_techniques", [])
    if match := next((t for t in techniques if t in available), None):
        st.session_state["technique_filter"] = match


def sidebar() -> list[Event]:
    st.sidebar.title("DetectForge")
    st.sidebar.caption("Adversarial validation and hardening of existing Sigma rules")
    data_dir = get_settings().data_dir
    events_path = st.sidebar.text_input("Events file (JSONL)", str(data_dir / "fixtures" / "events.jsonl"))
    try:
        events = load_events_cached(events_path, Path(events_path).stat().st_mtime)
    except (OSError, EventFileError) as e:
        st.sidebar.error(f"Cannot load events: {e}")
        events = []

    techniques = sorted({e.technique for e in events})
    st.session_state["available_techniques"] = techniques
    technique = st.sidebar.selectbox("Technique", ["(all)", *techniques], key="technique_filter")
    split = st.sidebar.radio("Split", ["(all)", "tune", "heldout"], horizontal=True)
    filtered = [
        e
        for e in events
        if (technique == "(all)" or e.technique == technique) and (split == "(all)" or e.split == split)
    ]
    attacks = sum(e.label == "attack" for e in filtered)
    st.sidebar.caption(f"{len(filtered)} events in scope: {attacks} attack, {len(filtered) - attacks} benign")

    st.sidebar.subheader("Pipeline")
    for step, status, note in PIPELINE:
        st.sidebar.markdown(f"{STATUS_ICON[status]} **{step}** — {note}")
    return filtered


def find_tab(index: ReferenceIndex | None) -> None:
    st.subheader("1 · Find existing rules")
    if index is None:
        st.info("No SigmaHQ index yet. Run `uv run detectforge sigmahq fetch`, then reload.")
    else:
        st.caption(f"SigmaHQ {index.release} — {len(index.rules)} Windows process-creation rules")
        c1, c2, c3 = st.columns([1, 2, 1])
        technique = c1.text_input("ATT&CK technique", "T1053.005")
        query = c2.text_input("Keywords (optional)", "schtasks create")
        limit = c3.slider("Max results", 1, 20, 8)
        exclude = st.checkbox(
            "Written-arm mode: exclude this technique's family and untagged rules",
            help="Used only to evaluate agent-written rules (secondary arm).",
        )
        try:
            hits = index.search(
                technique=None if exclude else (technique or None),
                query=query or None,
                limit=limit,
                exclude_technique=technique if exclude else None,
            )
        except ValueError as e:
            st.error(str(e))
            hits = []
        if not hits:
            st.warning("No usable rule found — this is where the write-new-rule fallback would start.")
        else:
            table(
                [
                    {
                        "title": h.rule.title,
                        "match": h.match,
                        "score": h.score,
                        "status": h.rule.status,
                        "level": h.rule.level,
                        "techniques": ", ".join(h.rule.techniques),
                        "evaluable": h.rule.evaluable,
                        "fields missing from events": ", ".join(h.rule.unmapped_fields),
                    }
                    for h in hits
                ],
            )
            choice = st.selectbox("Rule", range(len(hits)), format_func=lambda i: hits[i].rule.title)
            rule = hits[choice].rule
            with st.expander("Rule details (SigmaHQ text is untrusted input)"):
                st.markdown(f"`{rule.path}` · id `{rule.id}`")
                st.write(rule.description)
                if rule.falsepositives:
                    st.markdown("**Documented false positives:** " + "; ".join(rule.falsepositives))
                st.code(rule.rule_yaml, language="yaml")
            st.button(
                "Use this rule",
                type="primary",
                on_click=set_rule_under_test,
                args=(rule.rule_yaml, f"SigmaHQ: {rule.title}", rule.techniques),
            )

    st.divider()
    st.caption("Or start from a fixture rule (works without the SigmaHQ index)")
    fixture_dir = get_settings().data_dir / "fixtures" / "rules"
    fixtures = sorted(fixture_dir.glob("*.yml"))
    if fixtures:
        c1, c2 = st.columns([3, 1])
        path = c1.selectbox("Fixture rule", fixtures, format_func=lambda p: p.name)
        text = path.read_text(encoding="utf-8")
        c2.button(
            "Use fixture",
            on_click=set_rule_under_test,
            args=(text, f"fixture: {path.name}", techniques_from_tags(yaml.safe_load(text).get("tags", []))),
        )
    if label := st.session_state.get("rule_label"):
        st.success(f"Rule under test: {label}. Open the Validate tab.")


def scorecard_view(card: Scorecard, events: list[Event]) -> None:
    if not card.valid:
        st.error(f"Rule could not be evaluated: {card.error}")
        return
    attacks = card.hits + card.misses
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Attacks detected", f"{card.hits}/{attacks}")
    c2.metric("Evasion resistance (mutations)", pct(evasion_resistance(card)))
    c3.metric("False alarms", card.false_alarms)
    c4.metric("Benign events", sum(b.benign for b in card.per_transform.values()))
    st.markdown("**Per transform**")
    table(
        [
            {
                "transform": t,
                "attacks": b.attacks,
                "detected": b.hits,
                "resistance": pct(b.hits / b.attacks) if b.attacks else "n/a",
                "benign": b.benign,
                "false alarms": b.false_alarms,
            }
            for t, b in card.per_transform.items()
            if b.attacks or b.benign
        ],
    )
    matched = set(card.matched_event_ids)
    st.markdown("**Events**")
    table(
        [
            {
                "event": e.event_id,
                "label": e.label,
                "transform": e.transform,
                "split": e.split,
                "fired": e.event_id in matched,
                "outcome": outcome(e, e.event_id in matched),
                "command_line": e.command_line,
            }
            for e in events
        ],
    )


def outcome(event: Event, fired: bool) -> str:
    if event.label == "attack":
        return "detected" if fired else "MISSED"
    return "FALSE ALARM" if fired else "ok"


def validate_tab(events: list[Event]) -> None:
    st.subheader("2 · Adversarially validate (the “before”)")
    rule_yaml = st.session_state.get("before_yaml")
    if not rule_yaml:
        st.info("Pick a rule in the Find tab first.")
        return
    st.caption(st.session_state.get("rule_label", ""))
    validation_view(rule_yaml)
    with st.expander("Rule YAML"):
        st.code(rule_yaml, language="yaml")
    scorecard_view(run(rule_yaml, events), events)


def validation_view(rule_yaml: str) -> None:
    result = validate_rule(rule_yaml)
    for error in result.errors:
        st.error(error)
    for warning in result.warnings:
        st.warning(warning)
    if result.valid and not result.warnings:
        st.success("Valid Sigma rule, in scope, evaluable by the harness.")


def harden_tab(events: list[Event]) -> None:
    st.subheader("3 · Harden and re-validate (before vs after)")
    before = st.session_state.get("before_yaml")
    if not before:
        st.info("Pick a rule in the Find tab first.")
        return
    st.caption("Manual for now: edit the rule on the right. In W4 the agent fills this editor.")
    left, right = st.columns(2)
    left.markdown("**Before (as-is)**")
    left.code(before, language="yaml")
    right.markdown("**After (hardened candidate)**")
    after = right.text_area("after", key="after_editor", height=420, label_visibility="collapsed")
    right.button("Reset to before", on_click=lambda: st.session_state.update(after_editor=before))

    validation_view(after)
    report = compare(before, after, events)
    if not report.valid:
        st.error(report.after.error or report.before.error)
        return

    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Evasion resistance",
        pct(report.evasion_resistance_after),
        delta=None if report.evasion_resistance_delta is None else f"{report.evasion_resistance_delta:+.0%}",
    )
    c2.metric("Attacks detected", f"{report.after.hits}", delta=report.after.hits - report.before.hits)
    c3.metric(
        "False alarms",
        report.false_alarms_after,
        delta=report.false_alarms_after - report.false_alarms_before,
        delta_color="inverse",
    )
    table(
        [
            {
                "transform": t,
                "attacks": d.attacks,
                "before": pct(d.resistance_before),
                "after": pct(d.resistance_after),
                "false alarms before": d.false_alarms_before,
                "false alarms after": d.false_alarms_after,
            }
            for t, d in report.per_transform.items()
            if t in TRANSFORMS and (d.attacks or d.benign)
        ],
    )
    by_id = {e.event_id: e for e in events}
    for title, ids, kind in [
        ("Newly detected attacks", report.newly_detected_event_ids, st.success),
        ("Attacks LOST (regression)", report.lost_event_ids, st.error),
        ("New false alarms", report.new_false_alarm_event_ids, st.error),
        ("False alarms removed", report.removed_false_alarm_event_ids, st.success),
    ]:
        if ids:
            kind(f"**{title}:** " + ", ".join(f"`{i}` ({by_id[i].transform})" for i in ids))


def main() -> None:
    st.set_page_config(page_title="DetectForge", page_icon="🛡️", layout="wide")
    events = sidebar()
    index = load_index(str(get_settings().data_dir / "sigmahq"))
    find, validate, harden = st.tabs(["1 · Find", "2 · Validate", "3 · Harden"])
    with find:
        find_tab(index)
    with validate:
        validate_tab(events)
    with harden:
        harden_tab(events)


main()
