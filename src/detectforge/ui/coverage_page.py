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
from detectforge.ui import techniques as tx
from detectforge.ui.components import md, pct, table
from detectforge.ui.navigation import go, go_button, header, open_rule

_TACTIC = re.compile(r"^attack\.([a-z][a-z_-]+)$")  # attack.persistence, not attack.t1053 / attack.g0016


class RunCell(BaseModel):
    status: str
    heldout_before: float | None
    heldout_after: float | None
    heldout_mutations: int = 0  # 0: no held-out mutation types for this rule, so held-out is n/a
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


def _in_use(cells: list[RunCell]) -> RunCell:
    """The run that stands for a rule on the posture view (cells are newest first).

    The approved version is what a team would deploy, so it wins. Without one, the newest proposal
    still waiting for a reviewer. Only if every proposal was rejected, the newest rejected one, which
    the card then labels as rejected (the community rule stays in use).
    """
    for wanted in ("approved", "pending review"):
        if found := next((c for c in cells if c.decision == wanted), None):
            return found
    return cells[0]


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

    # Every run of each rule, then the one that represents it today (see _in_use): the approved version
    # if there is one, never simply the newest run, which may be a rejected attempt.
    hardened_runs: dict[str, list[RunCell]] = {}  # by normalized original rule text
    written_runs: dict[str, list[RunCell]] = {}  # by technique
    for summary in list_runs(runs_dir):  # newest first
        cell = RunCell(
            status=summary.status,
            heldout_before=summary.heldout_before,
            heldout_after=summary.heldout_after,
            heldout_mutations=summary.heldout_mutations,
            decision=summary.decision.decision if summary.decision else "pending review",
        )
        if summary.mode == "write":
            written_runs.setdefault(summary.technique, []).append(cell)
        else:
            original = _normalized(load_run(runs_dir, summary.trace_id).run.original_rule_yaml)
            hardened_runs.setdefault(original, []).append(cell)
    hardened = {k: _in_use(v) for k, v in hardened_runs.items()}
    written = {k: _in_use(v) for k, v in written_runs.items()}

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


def _heldout_text(cell: RunCell) -> str:
    """Before → after on held-out mutations; n/a when the rule has none (not 0%, not 100%)."""
    if cell.heldout_mutations == 0:
        return "n/a (no held-out mutations)"
    after = "not evaluable" if cell.heldout_after is None else pct(cell.heldout_after)
    return f"{pct(cell.heldout_before)} → {after}"


def _run_text(cell: RunCell | None) -> str:
    if cell is None:
        return "—"
    result = "passed gate" if cell.status == "passed" else "needs review"
    return f"{_heldout_text(cell)} · {result} · {cell.decision}"


def scored_hardened(rows: list[CoverageRow]) -> list[RunCell]:
    """Hardening runs that have a held-out score: the rule has held-out mutations."""
    return [r.hardened for r in rows if r.hardened and r.hardened.heldout_mutations > 0]


def best_hardened(rows: list[CoverageRow]) -> RunCell | None:
    return max(scored_hardened(rows), key=lambda c: c.heldout_after or 0.0, default=None)


class HeldoutMean(BaseModel):
    """Mean held-out resistance before → after hardening, over rules with held-out mutations only.

    Same rule as the batch output (agent/batch.heldout_summary): a rule with no held-out mutation is
    n/a and left out; a hardened rule that can't be evaluated counts as 0, never dropped.
    """

    hardened: int
    with_heldout: int
    before: float | None
    after: float | None


def heldout_mean(rows: list[CoverageRow]) -> HeldoutMean:
    cells = scored_hardened(rows)

    def mean(values: list[float | None]) -> float | None:
        return sum(v or 0.0 for v in values) / len(values) if values else None

    return HeldoutMean(
        hardened=sum(1 for r in rows if r.hardened),
        with_heldout=len(cells),
        before=mean([c.heldout_before for c in cells]),
        after=mean([c.heldout_after for c in cells]),
    )


def coverage_page(data_dir: Path, runs_dir: Path, rule_texts: dict[str, str], pending: int) -> None:
    header(
        "coverage",
        "Where each detection rule stands against attacker variations, and what the agent and your "
        "reviewers changed.",
    )
    eval_dir = data_dir / "eval"
    rows = coverage_rows(
        eval_dir / "selection.yml", eval_dir / "results" / "arm1_community.json", runs_dir, rule_texts
    )
    if not rows:
        _actions(pending)
        st.info(
            "No evaluated rules yet. Build the rule set with `detectforge dataset select`, then score the "
            "community rules with `detectforge eval community`."
        )
        return

    scored = [r for r in rows if r.community is not None]
    evaded = [r for r in scored if r.evaded_by]
    by_technique: dict[str, list[CoverageRow]] = {}
    for r in rows:
        by_technique.setdefault(r.technique, []).append(r)
    st.markdown(
        f"#### {len(evaded)} of {len(scored)} community rules miss at least one attacker variation, across "
        f"{sum(1 for rs in by_technique.values() if any(r.evaded_by for r in rs))} of "
        f"{len(by_technique)} techniques."
    )
    _actions(pending)

    approved = sum(
        1 for r in rows for c in (r.hardened, r.written) if c is not None and c.decision == "approved"
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Techniques", len(by_technique))
    c1.caption("Attacker behaviours your rules are meant to catch.")
    c2.metric(
        "Rules evaded as published",
        f"{len(evaded)}/{len(scored)}",
        help="At least one attacker variation slips past the community rule as published.",
    )
    c2.caption(
        f"Measured rules an attacker can disguise their way past ({len(rows) - len(scored)} not measured)."
    )
    c3.metric("Hardened by the agent", sum(1 for r in rows if r.hardened))
    c3.caption("Rules the agent proposed a stronger version of.")
    c4.metric("Approved changes", approved)
    c4.caption("Improvements a person signed off, ready to deploy.")

    st.subheader("Your coverage, by what the attacker is trying to do")
    st.caption(
        "Each tile is an attacker technique, grouped by goal. Colour = how much of the disguised versions "
        "your rules catch today (with an approved fix counted). Green: all · amber: some slip past · red: "
        "most slip past · grey: no variations to test yet."
    )
    st.html(goal_map(by_technique))

    st.subheader("What to work on next")
    st.caption(
        "Ranked automatically by risk: how much slips past, times how severe the rule says the behaviour is, "
        "lower when an approved fix exists. You don't have to choose; start at the top."
    )
    _priority_queue(rows, rule_texts)

    head, choice = st.columns([3, 1], vertical_alignment="bottom")
    head.subheader("Techniques")
    show_all = choice.toggle("Show every technique", key="posture_all")
    ordered = sorted(by_technique.items(), key=lambda kv: _worst(kv[1]))
    shown = [(t, rs) for t, rs in ordered if show_all or _needs_attention(rs)]
    st.caption(
        "Weakest first. 🟩 every variation caught · 🟧 some slip past · 🟥 most slip past · "
        "⬜ not measured. Each card opens its weakest rule to test or harden."
        + ("" if show_all else f" {len(ordered) - len(shown)} fully covered techniques hidden.")
    )
    for start in range(0, len(shown), 3):
        columns = st.columns(3)
        for column, (technique, rs) in zip(columns, shown[start : start + 3], strict=False):
            with column:
                _technique_card(technique, rs, rule_texts)

    summary = heldout_mean(rows)
    with st.expander("Before and after hardening (chart)", expanded=bool(summary.with_heldout)):
        if chart := resistance_chart(by_technique):
            st.vega_lite_chart(chart, width="stretch")
            st.caption(
                "The same rule before and after hardening, on variation types the agent never saw. Each "
                "rule shows the version in use today: the approved one, else the newest waiting for a "
                f"reviewer. Mean over those {summary.with_heldout} rules: {pct(summary.before)} → "
                f"{pct(summary.after)}. The report's evaluation is different on purpose: it averages all "
                "3 runs of each test rule, accepted or not, so one lucky run can't flatter it."
            )
        else:
            st.caption("No hardened rule with unseen variations to compare yet.")

    with st.expander("Every rule (table, report download)"):
        _rules_table(rows, rule_texts)


LEVEL_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0.5}


def _level(rule_yaml: str | None) -> str:
    try:
        return str((yaml.safe_load(rule_yaml or "") or {}).get("level") or "medium")
    except yaml.YAMLError:
        return "medium"


def effective(rows: list[CoverageRow]) -> float | None:
    """A technique's coverage today: its weakest rule, counting an approved fix's unseen score."""
    scores = []
    for r in rows:
        if r.community is None:
            continue
        fixed = next(
            (c for c in (r.hardened, r.written) if c and c.decision == "approved" and c.heldout_mutations),
            None,
        )
        scores.append(max(r.community, fixed.heldout_after or 0.0) if fixed else r.community)
    return min(scores) if scores else None


def _tile_color(score: float | None) -> str:
    if score is None:
        return "#334155"
    if score >= 1:
        return "#166534"
    return "#B45309" if score >= 0.5 else "#B91C1C"


def goal_map(by_technique: dict[str, list[CoverageRow]]) -> str:
    """Tiles per attacker goal. Built only from our own technique names and numbers (no rule text)."""
    groups: dict[str, list[str]] = {}
    for tid in by_technique:
        groups.setdefault(tx.goal(tid).label, []).append(tid)
    parts = [
        "<style>.gm{display:flex;flex-direction:column;gap:.55rem}.gr{display:flex;gap:.5rem;align-items:"
        "stretch;flex-wrap:wrap}.gl{flex:0 0 190px;color:#C7D3E6;font-weight:600;font-size:.9rem;padding-top"
        ":.45rem}.tl{flex:0 1 170px;border-radius:.55rem;padding:.45rem .6rem;color:#fff;font-size:.8rem;"
        "line-height:1.25}.tl b{display:block;font-size:.95rem}.tl small{opacity:.8}</style><div class='gm'>"
    ]
    for label, tids in sorted(groups.items()):
        icon = tx.goal(tids[0]).icon
        tiles = []
        for tid in sorted(tids, key=lambda t: effective(by_technique[t]) or 2):
            score = effective(by_technique[tid])
            shown = "not tested" if score is None else f"{score:.0%} caught"
            tiles.append(
                f"<div class='tl' style='background:{_tile_color(score)}'><b>{shown}</b>"
                f"{tx.technique(tid).name}<br><small>{tid}</small></div>"
            )
        parts.append(f"<div class='gr'><div class='gl'>{icon} {label}</div>{''.join(tiles)}</div>")
    return "".join(parts) + "</div>"


def _priority_queue(rows: list[CoverageRow], rule_texts: dict[str, str], top: int = 5) -> None:
    ranked = []
    for r in rows:
        if r.community is None or r.community >= 1:
            continue
        level = _level(rule_texts.get(r.rule_id))
        fix = next((c for c in (r.hardened, r.written) if c and c.decision == "approved"), None)
        waiting = any(c and c.decision == "pending review" for c in (r.hardened, r.written))
        today = effective([r]) or 0.0  # with an approved fix counted at what it really catches
        if today >= 1:
            continue
        risk = (1 - today) * LEVEL_WEIGHT.get(level, 2)
        ranked.append((risk, r, level, fix, waiting))
    if not ranked:
        st.success("Every measured rule catches every variation we have. Nothing to do.")
        return
    for i, (_risk, r, level, fix, waiting) in enumerate(sorted(ranked, key=lambda x: -x[0])[:top], 1):
        with st.container(border=True):
            left, right = st.columns([4, 1], vertical_alignment="center")
            left.markdown(f"**{i}. {tx.label(r.technique)}** · {level} severity")
            approved = fix is not None
            if fix and fix.heldout_mutations and (fix.heldout_after or 0) <= (fix.heldout_before or 0):
                why = (
                    f"an approved fix exists but still catches only {pct(fix.heldout_after)} of unseen "
                    "variations: harden it again or write a new rule"
                )
            elif fix:
                why = f"an approved fix catches {_heldout_text(fix)} of unseen variations; deploy it"
            elif waiting:
                why = "a fix is waiting for a reviewer"
            else:
                why = "no fix yet: test it and let the agent harden it"
            left.caption(
                f"{md(r.title)}: catches {pct(r.community)} of disguised attacks as published "
                f"(beaten by {', '.join(r.evaded_by)}) · {why}."
            )
            if waiting and not approved:
                right.button("Review it →", key=f"pq_review_{r.rule_id}", on_click=go, args=("review",))
            elif r.rule_id in rule_texts:
                right.button(
                    "Open rule →",
                    key=f"pq_{r.rule_id}",
                    on_click=open_rule,
                    args=(rule_texts[r.rule_id], f"SigmaHQ: {r.title}", [r.technique]),
                )


def _needs_attention(rows: list[CoverageRow]) -> bool:
    return any(r.evaded_by or r.community is None for r in rows)


def _technique_card(technique: str, rows: list[CoverageRow], rule_texts: dict[str, str]) -> None:
    weakest = min(rows, key=lambda r: r.community if r.community is not None else 2.0)
    evaded_by = sorted({x for r in rows for x in r.evaded_by})
    with st.container(border=True):
        st.markdown(f"**{tx.label(technique)}** &nbsp; {badge(weakest.community)}")
        st.caption(", ".join(sorted({x for r in rows for x in r.tactics})) or "no tactic tag")
        st.markdown(
            f"{len(rows)} rule{'s' if len(rows) != 1 else ''} · weakest: {md(weakest.title)}",
            help="The community rule that catches the fewest attacker variations, as published.",
        )
        if evaded_by:
            st.caption("Evaded by " + ", ".join(evaded_by))
        elif all(r.community is None for r in rows):
            st.caption("No attacker variations exist for these rules yet, so their resistance is unknown.")
        else:
            st.caption("Every attacker variation we have is caught.")
        best = best_hardened(rows)
        if best and best.decision == "rejected":
            st.caption(
                f"Hardening proposed ({_heldout_text(best)} of unseen variations) but rejected by a "
                "reviewer: the community rule stays in use."
            )
        elif best:
            state = "approved" if best.decision == "approved" else "waiting for a reviewer"
            st.caption(f"After hardening: {_heldout_text(best)} of unseen variations · {state}")
        elif any(r.hardened for r in rows):
            st.caption("Hardened; no unseen variations to measure it on.")
        if weakest.rule_id in rule_texts:
            st.button(
                "Open weakest rule →",
                key=f"card_{technique}",
                on_click=open_rule,
                args=(rule_texts[weakest.rule_id], f"SigmaHQ: {weakest.title}", [technique]),
            )


def _rules_table(rows: list[CoverageRow], rule_texts: dict[str, str]) -> None:
    st.caption(
        "Agent columns show variation types the agent never saw: before → after, the quality checks' "
        "verdict, and the reviewer's decision."
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
                "hardened (unseen)": _run_text(r.hardened),
                "written (unseen)": _run_text(r.written),
            }
            for r in shown
        ]
    )
    openable = [r for r in shown if r.rule_id in rule_texts]
    if openable:
        c1, c2 = st.columns([3, 1], vertical_alignment="bottom")
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


def _best_text(rows: list[CoverageRow]) -> str:
    if best := best_hardened(rows):
        return _heldout_text(best)
    return "n/a (no held-out mutations)" if any(r.hardened for r in rows) else "—"


def _actions(pending: int) -> None:
    """The three jobs people come here for, one click each."""
    waiting = f"{pending} proposal{'s' if pending != 1 else ''} waiting" if pending else "Nothing waiting"
    c1, c2, c3, _ = st.columns([1.2, 1, 1.3, 2], vertical_alignment="center")
    with c1:
        go_button("request", "Check a new threat →", primary=True)
    with c2:
        go_button("rules", "Test a rule →")
    with c3:
        go_button("review", "Open the review queue →")
    st.caption(f"Review: {waiting} for a decision.")


def coverage_report(rows: list[CoverageRow]) -> str:
    """Markdown report for sharing (e.g. with management or an auditor). Rule titles are SigmaHQ text."""
    scored = [r for r in rows if r.community is not None]
    evaded = [r for r in scored if r.evaded_by]
    mean = heldout_mean(rows)
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
        f"- Held-out evasion resistance, mean over the {mean.with_heldout} hardened rules with held-out "
        f"mutations: {pct(mean.before)} → {pct(mean.after)} (rules without held-out mutations are n/a)",
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


BEFORE = "Before hardening (held-out)"
AFTER = "After hardening (held-out)"


def resistance_chart(by_technique: dict[str, list[CoverageRow]]) -> dict | None:
    """Grouped bars per technique: held-out evasion resistance before vs after hardening.

    Both bars are the same rule (the technique's best hardening run) on the same held-out events, so
    the gap is the hardening's effect and nothing else. Techniques with no hardening run that has
    held-out mutations aren't shown (n/a). A Vega-Lite spec with its data inline; technique ids are
    validated ATT&CK ids, so nothing untrusted reaches the chart.
    """
    values = []
    for technique, rs in by_technique.items():
        if (best := best_hardened(rs)) is None:
            continue
        values.append({"technique": technique, "series": BEFORE, "resistance": best.heldout_before or 0.0})
        values.append({"technique": technique, "series": AFTER, "resistance": best.heldout_after or 0.0})
    if not values:
        return None
    order = sorted({v["technique"] for v in values}, key=lambda t: _worst(by_technique[t]))
    return {
        "data": {"values": values},
        "height": {"step": 13},
        "mark": {"type": "bar", "cornerRadiusEnd": 3},
        "encoding": {
            "y": {"field": "technique", "type": "nominal", "sort": order, "title": None},
            "yOffset": {"field": "series", "sort": [BEFORE, AFTER]},
            "x": {
                "field": "resistance",
                "type": "quantitative",
                "title": "Evasion resistance (share of attacker variations detected)",
                "scale": {"domain": [0, 1]},
                "axis": {"format": "%"},
            },
            "color": {
                "field": "series",
                "type": "nominal",
                "title": None,
                "scale": {"domain": [BEFORE, AFTER], "range": ["#F59E0B", "#3B82F6"]},
                "legend": {"orient": "top"},
            },
            "tooltip": [
                {"field": "technique"},
                {"field": "series", "title": "measured"},
                {"field": "resistance", "format": ".0%"},
            ],
        },
    }
