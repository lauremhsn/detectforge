"""Reports: a summary to send, built for its reader (a manager, or an engineer) from chosen sections.

Every number comes from the same functions as the Posture page and the Lab, so the report never says
something the app doesn't. Rule titles are SigmaHQ or model text, escaped like everywhere else.
"""

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st

from detectforge.ui.components import md, pct
from detectforge.ui.coverage_page import CoverageRow, coverage_rows
from detectforge.ui.navigation import header
from detectforge.ui.results import headline
from detectforge.ui.techniques import goal, technique

AUDIENCES = {
    "manager": "Manager or auditor: one page, plain words, what it means for risk",
    "engineer": "Detection engineer: per technique and per rule, with evidence",
}
SECTIONS = {
    "summary": "Summary and key numbers",
    "goals": "Coverage by attacker goal",
    "weakest": "Weakest techniques (where to act first)",
    "changes": "What changed: approved and waiting changes",
    "rules": "Every rule (engineers)",
    "method": "How it was measured, and its limits",
}
DEFAULTS = {"manager": ["summary", "goals", "weakest", "changes"], "engineer": list(SECTIONS)}


def _status(r: CoverageRow) -> str:
    if r.community is None:
        return "not measured"
    if r.community >= 1:
        return "fully covered"
    return "evadable" if r.community >= 0.5 else "mostly evadable"


def build_report(
    rows: list[CoverageRow], data_dir: Path, runs_dir: Path, audience: str, sections: list[str]
) -> str:
    h = headline(data_dir, runs_dir)
    scored = [r for r in rows if r.community is not None]
    evaded = [r for r in scored if r.evaded_by]
    approved = [c for r in rows for c in (r.hardened, r.written) if c and c.decision == "approved"]
    waiting = [c for r in rows for c in (r.hardened, r.written) if c and c.decision == "pending review"]
    out = [
        "# Detection coverage report",
        "",
        f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC by DetectForge · for: {AUDIENCES[audience].split(':')[0]}",
        "",
    ]
    if "summary" in sections:
        out += [
            "## Summary",
            "",
            f"- **{len(evaded)} of {len(scored)}** measured detection rules let at least one disguised version "
            "of the attack through, as published.",
            f"- On the test techniques, community rules as published caught **{pct(h.community_unseen)}** "
            "of the disguised attacks.",
            f"- Where the agent hardened a rule, unseen variations caught went from **{pct(h.hardened.before)} "
            f"to {pct(h.hardened.after)}**, with {h.hardened.new_false_alarm_runs} new false alarms.",
            f"- **{len(approved)}** rules have an agent-improved version a person approved, ready to deploy; "
            f"**{len(waiting)}** have one waiting for a decision. Nothing is deployed without a person's approval.",
            "",
        ]
    if "goals" in sections:
        by_goal: dict[str, list[CoverageRow]] = defaultdict(list)
        for r in rows:
            by_goal[goal(r.technique).label].append(r)
        out += ["## Coverage by attacker goal", "", "| Attacker goal | Rules | Fully covered | Evadable | Not measured |",
                "|---|---|---|---|---|"]  # fmt: skip
        for label, rs in sorted(by_goal.items()):
            counts = defaultdict(int)
            for r in rs:
                counts[_status(r)] += 1
            out.append(
                f"| {label} | {len(rs)} | {counts['fully covered']} | "
                f"{counts['evadable'] + counts['mostly evadable']} | {counts['not measured']} |"
            )
        out.append("")
    if "weakest" in sections:
        weak = sorted(evaded, key=lambda r: r.community or 0)[:5]
        out += ["## Where to act first", ""]
        for r in weak:
            t = technique(r.technique)
            fix = "approved fix ready" if any(c and c.decision == "approved" for c in (r.hardened, r.written)) \
                else "no approved fix yet"  # fmt: skip
            out.append(
                f"- **{t.name}** ({r.technique}): the rule catches {pct(r.community)} of attack variations; "
                f"evaded by {', '.join(r.evaded_by)}; {fix}."
            )
        out.append("")
    if "changes" in sections:
        out += ["## Changes", "", f"- Approved: {len(approved)} · waiting: {len(waiting)}", ""]
    if "rules" in sections:
        out += ["## Every rule", "", "| Technique | Rule | As published | Evaded by | Agent version (unseen) | Decision |",
                "|---|---|---|---|---|---|"]  # fmt: skip
        for r in sorted(rows, key=lambda r: (r.technique, r.title)):
            cell = r.hardened or r.written
            agent = (
                f"{pct(cell.heldout_before)} → {pct(cell.heldout_after)}"
                if cell and cell.heldout_mutations
                else "—"
            )
            cells = [r.technique, md(r.title), pct(r.community), ", ".join(r.evaded_by) or "none", agent,
                     cell.decision if cell else "—"]  # fmt: skip
            out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
        out.append("")
    if "method" in sections:
        out += [
            "## How it was measured",
            "",
            "Each rule is replayed against attack commands from Atomic Red Team and versions of them disguised "
            "with five published evasion tricks (inserted characters, swapped flags, shortened names, "
            "reordering, re-encoding), plus legitimate commands that look similar. The agent improves rules "
            "using only some trick types; it is judged on the others, which it never sees.",
            "",
            "Limits: Windows process-creation rules only; generated attack variations, not a real breach; not "
            "connected to a live SIEM; no rule is evasion-proof.",
            "",
        ]
    return "\n".join(out)


def reports_page(data_dir: Path, runs_dir: Path, rule_texts: dict[str, str]) -> None:
    header("reports", "Build a report for its reader, choose what goes in, preview it, and download it.")
    eval_dir = data_dir / "eval"
    rows = coverage_rows(
        eval_dir / "selection.yml", eval_dir / "results" / "arm1_community.json", runs_dir, rule_texts
    )
    if not rows:
        st.info("No evaluated rules yet, so there is nothing to report.")
        return
    left, right = st.columns([1, 2])
    with left:
        audience = st.radio(
            "Who is it for?", list(AUDIENCES), format_func=AUDIENCES.get, key="report_audience"
        )
        st.session_state.setdefault("report_sections", DEFAULTS[audience])
        if st.session_state.get("report_for") != audience:
            st.session_state["report_sections"] = DEFAULTS[audience]
            st.session_state["report_for"] = audience
        sections = st.multiselect("Sections", list(SECTIONS), format_func=SECTIONS.get, key="report_sections")
    report = build_report(rows, data_dir, runs_dir, audience, sections)
    with right:
        st.download_button(
            "Download (Markdown)", report, file_name=f"detectforge-report-{audience}.md", type="primary"
        )
        with st.container(border=True, height=560):
            st.markdown(report)
