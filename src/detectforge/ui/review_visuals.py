"""Visual pieces of a review: which path the agent took, what it found → changed → achieved, checks.

Everything inserted into HTML is escaped (gate details can quote rule text, which is model output).
"""

import difflib
import html
import re

import streamlit as st
import yaml

from detectforge.agent.runner import HardeningOutcome
from detectforge.harness.compare import HardeningReport
from detectforge.ui import techniques as tx
from detectforge.ui.components import md, pct

_BADGE = (
    "<div style='display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:-.2rem 0 .6rem 0'>"
    "<span style='background:{bg};color:#fff;border-radius:999px;padding:.3rem .8rem;font-weight:600;"
    "font-size:.88rem'>{route}</span>"
    "<span style='background:#D6E2F5;color:#1E2B45;border-radius:999px;padding:.3rem .8rem;font-size:.85rem'>"
    "{technique}</span>"
    "<span style='color:#4B5B73;font-size:.8rem'>agent cost: {calls} model calls · {tokens} tokens</span></div>"
)


def route_badge(mode: str, technique: str, calls: int, tokens: int) -> str:
    if mode == "write":
        route, bg = "✍️ Written from scratch: community rules hidden", "#7C3AED"
    else:
        route, bg = "🛠️ Hardened an existing community rule", "#2563EB"
    return _BADGE.format(
        bg=bg,
        route=route,
        technique=html.escape(tx.label(technique)),
        calls=calls,
        tokens=f"{tokens / 1000:.0f}k" if tokens >= 1000 else tokens,
    )


def _detection_lines(rule_yaml: str) -> list[str]:
    try:
        detection = (yaml.safe_load(rule_yaml or "") or {}).get("detection") or {}
    except yaml.YAMLError:
        return []
    return yaml.safe_dump(detection, sort_keys=False, allow_unicode=True).splitlines()


def story(outcome: HardeningOutcome) -> None:
    """Found → changed → result, from recorded numbers; then the agent's own explanation."""
    run, heldout = outcome.run, outcome.heldout_evaluation
    c1, c2, c3 = st.columns(3)
    with c1.container(border=True):
        st.markdown("**1 · What it found**")
        if run.mode == "write":
            st.caption("No rule to start from (community rules for this technique were hidden).")
        elif run.tuning_evasion_resistance_before is None:
            st.caption("The community rule had no variations it could be tested on.")
        else:
            st.caption(
                f"The community rule caught **{pct(run.tuning_evasion_resistance_before)}** of the disguised "
                f"attacks the agent could test, with {run.tuning_false_alarms_before} false alarm(s)."
            )
    with c2.container(border=True):
        st.markdown("**2 · What it changed**")
        if run.mode == "write":
            lines = _detection_lines(run.final_rule_yaml)
            st.caption(f"Wrote a new rule: {len(lines)} lines of detection logic.")
        else:
            diff = list(
                difflib.unified_diff(
                    _detection_lines(run.original_rule_yaml),
                    _detection_lines(run.final_rule_yaml),
                    lineterm="",
                )
            )
            added = sum(d.startswith("+") and not d.startswith("+++") for d in diff)
            removed = sum(d.startswith("-") and not d.startswith("---") for d in diff)
            st.caption(f"Edited the detection logic: **+{added}** lines added, **{removed}** removed.")
    with c3.container(border=True):
        st.markdown("**3 · What that did**")
        unseen = (
            f"{pct(heldout.evasion_resistance_before)} → **{pct(heldout.evasion_resistance_after)}**"
            if heldout and heldout.mutated_attacks
            else "n/a (no unseen variations)"
        )
        st.caption(
            f"Tested variations: **{pct(run.tuning_evasion_resistance_after)}** caught. Unseen variations: "
            f"{unseen}. New false alarms on unseen look-alikes: "
            f"{len(heldout.new_false_alarm_event_ids) if heldout else 'n/a'}."
        )
    if run.rationale:
        with st.expander("Why the agent changed it, in its own words", expanded=True):
            st.markdown("\n".join(f"- {point}" for point in rationale_points(run.rationale)))
            st.caption("The agent's explanation is a claim; the numbers above are measured.")


_MARKER = re.compile(r"^\s*(?:[-*•]\s+|\d+[.)]\s*)")


def rationale_points(text: str, limit: int = 14) -> list[str]:
    """The agent's explanation as short points, safe to render.

    Keeps the model's own line breaks and numbered items (a lone "1." joins the next line); a long
    paragraph is split into sentences. Model output is escaped first, so an injected link, image or
    "approved" banner can't render; only inline code is let back in (it can't carry a link), and bold markers are removed.
    """
    lines, carry = [], ""
    for raw in text.splitlines():
        line = _MARKER.sub("", raw).strip()
        if not line:
            continue
        if re.fullmatch(r"\d+[.)]?", raw.strip()):
            continue
        if carry:
            line, carry = f"{carry} {line}", ""
        if line.endswith(":") and len(line) < 60:
            carry = line
            continue
        lines += [s for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", line) if s] if len(line) > 220 else [line]
    if carry:
        lines.append(carry)
    safe = []
    for line in lines[:limit]:
        escaped = md(line)
        # Bold stays literal (shown as **text**): a bold "APPROVED" line from the model must not look official.
        # A code span shows its text literally (no links), so its own escapes are taken back out.
        escaped = re.sub(r"\\`(.+?)\\`", lambda m: "`" + re.sub(r"\\(.)", r"\1", m.group(1)) + "`", escaped)
        safe.append(escaped)
    return safe


def check_chips(checks) -> str:
    chips = []
    for c in checks:
        if c.passed:
            bg, fg, mark = "#DCFCE7", "#166534", "✓"
        elif c.blocking:
            bg, fg, mark = "#FEE2E2", "#991B1B", "✗"
        else:
            bg, fg, mark = "#FEF3C7", "#92400E", "!"
        chips.append(
            f"<span title='{html.escape(c.detail, quote=True)}' style='background:{bg};color:{fg};"
            "border-radius:999px;padding:.22rem .65rem;font-size:.8rem;white-space:nowrap'>"
            f"{mark} {html.escape(c.name.replace('_', ' '))}</span>"
        )
    legend = (
        "<div style='color:#4B5B73;font-size:.78rem;margin-top:.35rem'>✓ passed · ✗ failed (blocks "
        "approval by default) · ! warning, worth a look · hover a check for its detail</div>"
    )
    return f"<div style='display:flex;flex-wrap:wrap;gap:.35rem'>{''.join(chips)}</div>{legend}"


def variation_chart(heldout: HardeningReport) -> dict | None:
    values = []
    for t, d in heldout.per_transform.items():
        if t == "none" or not d.attacks:
            continue
        values.append({"type": t, "rule": "before", "caught": d.resistance_before or 0.0, "n": d.attacks})
        values.append({"type": t, "rule": "after", "caught": d.resistance_after or 0.0, "n": d.attacks})
    if not values:
        return None
    return {
        "data": {"values": values},
        "height": {"step": 16},
        "mark": {"type": "bar", "cornerRadiusEnd": 3},
        "encoding": {
            "y": {"field": "type", "type": "nominal", "title": None},
            "yOffset": {"field": "rule", "sort": ["before", "after"]},
            "x": {
                "field": "caught",
                "type": "quantitative",
                "scale": {"domain": [0, 1]},
                "axis": {"format": "%"},
                "title": "share of unseen disguised attacks caught",
            },
            "color": {
                "field": "rule",
                "type": "nominal",
                "title": None,
                "scale": {"domain": ["before", "after"], "range": ["#F59E0B", "#1F4FB8"]},
                "legend": {"orient": "top"},
            },
            "tooltip": [
                {"field": "type"},
                {"field": "rule"},
                {"field": "caught", "format": ".0%"},
                {"field": "n", "title": "attacks"},
            ],
        },
    }
