"""Coverage (home): "are we covered, and can we prove it?" for every evaluated rule, on one screen.

For a SOC lead or manager: how well each community rule holds up as-is (Arm 1), what evades it, what
the agent's hardening and writing achieved on held-out mutations, and what a reviewer approved, plus a
report to share. Everything is read from committed results and saved runs; nothing here calls the
model or recomputes a score.
"""

import re
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st
import yaml
from pydantic import BaseModel, ValidationError

from detectforge.eval.arms import ArmResult
from detectforge.review import list_runs, load_run
from detectforge.ui.components import md, pct, table
from detectforge.ui.navigation import go_button, header, open_rule

_TACTIC = re.compile(r"^attack\.([a-z][a-z_-]+)$")  # attack.persistence, not attack.t1053 / attack.g0016


class RunCell(BaseModel):
    status: str
    heldout_before: float | None
    heldout_after: float | None
    decision: str


class CoverageRow(BaseModel):
    rule_id: str
    title: str
    technique: str
    tactics: list[str] = []
    split: str
    community: float | None
    evaded_by: list[str]
    hardened: RunCell | None
    written: RunCell | None


def _normalized(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def tactics_of(rule_yaml: str | None) -> list[str]:
    try:
        tags = (yaml.safe_load(rule_yaml or "") or {}).get("tags") or []
    except yaml.YAMLError:
        return []
    return sorted({m.group(1).replace("_", "-") for t in tags if (m := _TACTIC.match(str(t)))})


def coverage_rows(
    selection_path: Path, arm1_path: Path, runs_dir: Path, rule_texts: dict[str, str]
) -> list[CoverageRow]:
    """One row per selected rule. rule_texts maps rule id -> community YAML (to find its hardening runs)."""
    selection = yaml.safe_load(selection_path.read_text(encoding="utf-8")) if selection_path.exists() else {}
    arm1 = {}
    if arm1_path.exists():
        try:
            arm1 = {r.rule_id: r for r in ArmResult.model_validate_json(arm1_path.read_text("utf-8")).rules}
        except ValidationError:
            arm1 = {}

    hardened: dict[str, RunCell] = {}  # by normalized original rule text; newest run wins
    written: dict[str, RunCell] = {}  # by technique
    for summary in list_runs(runs_dir):  # newest first
        cell = RunCell(
            status=summary.status,
            heldout_before=summary.heldout_before,
            heldout_after=summary.heldout_after,
            decision=summary.decision.decision if summary.decision else "pending review",
        )
        if summary.mode == "write":
            written.setdefault(summary.technique, cell)
        else:
            original = _normalized(load_run(runs_dir, summary.trace_id).run.original_rule_yaml)
            hardened.setdefault(original, cell)

    rows = []
    for rule in (selection or {}).get("rules", []):
        result = arm1.get(rule["id"])
        text = rule_texts.get(rule["id"])
        rows.append(
            CoverageRow(
                rule_id=rule["id"],
                title=rule["title"],
                technique=rule["technique"],
                tactics=tactics_of(text),
                split=rule.get("split", ""),
                community=result.evasion_resistance if result else None,
                evaded_by=result.evaded_by if result else [],
                hardened=hardened.get(_normalized(text)) if text else None,
                written=written.get(rule["technique"]),
            )
        )
    return rows


def badge(score: float | None) -> str:
    if score is None:
        return "⬜ not measured"
    if score >= 1:
        return f"🟩 {pct(score)}"
    return f"🟧 {pct(score)}" if score >= 0.5 else f"🟥 {pct(score)}"


def _run_text(cell: RunCell | None) -> str:
    if cell is None:
        return "—"
    result = "passed gate" if cell.status == "passed" else "needs review"
    return f"{pct(cell.heldout_before)} → {pct(cell.heldout_after)} · {result} · {cell.decision}"


def coverage_page(data_dir: Path, runs_dir: Path, rule_texts: dict[str, str], pending: int) -> None:
    header(
        "coverage",
        "Are we covered, and can we prove it? Each community rule is replayed on real attacks and on "
        "variations an attacker would use to slip past it; the agent hardens the weak ones, and a "
        "human approves every change.",
    )
    _guide(pending)

    eval_dir = data_dir / "eval"
    rows = coverage_rows(
        eval_dir / "selection.yml", eval_dir / "results" / "arm1_community.json", runs_dir, rule_texts
    )
    if not rows:
        st.info(
            "No evaluated rules yet. Build the rule set with `detectforge dataset select`, then score the "
            "community rules with `detectforge eval community`."
        )
        return

    scored = [r for r in rows if r.community is not None]
    evaded = [r for r in scored if r.evaded_by]
    approved = sum(
        1 for r in rows for c in (r.hardened, r.written) if c is not None and c.decision == "approved"
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Techniques", len({r.technique for r in rows}))
    c2.metric(
        "Rules evaded as published", f"{len(evaded)}/{len(scored)}", help="At least one mutation slips past."
    )
    c3.metric("Hardened by the agent", sum(1 for r in rows if r.hardened))
    c4.metric("Approved changes", approved)

    st.subheader("By technique")
    st.caption(
        "🟩 every variation detected · 🟧 some slip past · 🟥 most slip past (community rules as published)"
    )
    by_technique: dict[str, list[CoverageRow]] = {}
    for r in rows:
        by_technique.setdefault(r.technique, []).append(r)
    table(
        [
            {
                "technique": t,
                "tactic": ", ".join(sorted({x for r in rs for x in r.tactics})) or "—",
                "rules": len(rs),
                "weakest rule as published": badge(
                    min((r.community for r in rs if r.community is not None), default=None)
                ),
                "evaded by": ", ".join(sorted({x for r in rs for x in r.evaded_by})) or "—",
                "best hardened (held-out)": pct(
                    max(
                        (
                            r.hardened.heldout_after
                            for r in rs
                            if r.hardened and r.hardened.heldout_after is not None
                        ),
                        default=None,
                    )
                ),
            }
            for t, rs in sorted(by_technique.items(), key=lambda kv: _worst(kv[1]))
        ]
    )

    st.subheader("Rules")
    st.caption(
        "Agent columns show held-out mutations only (evasion types the agent never saw): before → after, "
        "the quality gate's verdict, and the reviewer's decision."
    )
    c1, c2 = st.columns([2, 1])
    split = c1.radio("Rules", ["all", "dev", "test"], horizontal=True, key="overview_split")
    only_evaded = c2.toggle("Only rules evaded as published", key="overview_evaded")
    shown = sorted(
        [r for r in rows if (split == "all" or r.split == split) and (not only_evaded or r.evaded_by)],
        key=lambda r: (r.community if r.community is not None else 2, r.technique),
    )
    table(
        [
            {
                "technique": r.technique,
                "rule": r.title,
                "split": r.split,
                "as published": badge(r.community),
                "evaded by": ", ".join(r.evaded_by) or ("none" if r.community is not None else "—"),
                "hardened (held-out)": _run_text(r.hardened),
                "written (held-out)": _run_text(r.written),
            }
            for r in shown
        ]
    )
    openable = [r for r in shown if r.rule_id in rule_texts]
    if openable:
        c1, c2 = st.columns([3, 1])
        pick = c1.selectbox(
            "Open a rule to test or harden it", openable, format_func=lambda r: f"{r.technique} · {r.title}"
        )
        c2.button(
            "Open in Rules →",
            on_click=open_rule,
            args=(rule_texts[pick.rule_id], f"SigmaHQ: {pick.title}", [pick.technique]),
        )
    st.download_button(
        "Download coverage report (Markdown)",
        coverage_report(rows),
        file_name="detectforge-coverage-report.md",
        help="A shareable summary: per-rule evasion resistance, agent results and review decisions.",
    )


def _guide(pending: int) -> None:
    with st.container(border=True):
        st.markdown("**What do you want to do?**")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**A new threat came in.** Paste the request or report; see whether you're covered.")
            go_button("request", "Check a threat →", primary=True)
        with c2:
            st.markdown(
                "**Find and fix weak rules.** Pick a rule below, test it against evasions, harden it."
            )
            go_button("rules", "Test a rule →")
        with c3:
            waiting = (
                f"{pending} proposal{'s' if pending != 1 else ''} waiting" if pending else "Nothing waiting"
            )
            st.markdown(f"**Approve changes.** {waiting} for a reviewer.")
            go_button("review", "Open the review queue →")


def coverage_report(rows: list[CoverageRow]) -> str:
    """Markdown report for sharing (e.g. with management or an auditor). Rule titles are SigmaHQ text."""
    scored = [r for r in rows if r.community is not None]
    evaded = [r for r in scored if r.evaded_by]
    lines = [
        "# DetectForge coverage report",
        "",
        f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC.",
        "",
        "Evasion resistance = share of behavior-preserving attack variations (insertion, substitution, "
        "omission, reordering, recoding) that a rule still detects. Agent results are measured on held-out "
        "variation types the agent never saw. Every change was proposed by the agent and decided by a human.",
        "",
        f"- Rules evaluated: {len(scored)} of {len(rows)}, "
        f"covering {len({r.technique for r in rows})} techniques",
        f"- Evaded by at least one variation as published: {len(evaded)}",
        f"- Hardened by the agent: {sum(1 for r in rows if r.hardened)}",
        "",
        "| Technique | Rule | As published | Evaded by | Hardened (held-out) | Written (held-out) |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=lambda r: (r.technique, r.title)):
        cells = [
            r.technique,
            md(r.title),
            pct(r.community),
            ", ".join(r.evaded_by) or "none",
            _run_text(r.hardened),
            _run_text(r.written),
        ]
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(lines) + "\n"


def _worst(rows: list[CoverageRow]) -> float:
    """Sort key: weakest technique first, techniques with no measurement last."""
    return min((r.community for r in rows if r.community is not None), default=2.0)
