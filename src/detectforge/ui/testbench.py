"""The visual test bench: every event a rule was replayed on, whether it fired, and where it matched.

A table of ids doesn't show *why* a disguised attack slipped past. Here each attack is shown with its
disguised versions under it, each command line with the text the rule looks for highlighted, and a
tick or cross per rule, so the original and the hardened rule can be compared on the very same events.

Highlighting is a reading aid computed here from the rule's CommandLine values (contains, startswith,
endswith, exact and regex): the verdict itself always comes from the harness. Command lines and rule
values are untrusted text, so everything is HTML-escaped.
"""

import contextlib
import html
import re
from collections import defaultdict

import yaml

from detectforge.schemas import Event

_FIELD = "commandline"


def rule_patterns(rule_yaml: str) -> list[re.Pattern]:
    """Case-insensitive patterns for the rule's CommandLine values (wildcards turned into .*)."""
    try:
        detection = (yaml.safe_load(rule_yaml or "") or {}).get("detection") or {}
    except yaml.YAMLError:
        return []
    found: list[re.Pattern] = []

    def visit(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                field, *mods = str(key).split("|")
                if field.lower() == _FIELD:
                    for v in value if isinstance(value, list) else [value]:
                        if isinstance(v, str) and v:
                            add(v, mods)
                else:
                    visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    def add(value: str, mods: list[str]) -> None:
        source = value if "re" in mods else ".*?".join(re.escape(part) for part in value.split("*"))
        with contextlib.suppress(re.error):
            found.append(re.compile(source, re.IGNORECASE))

    visit({k: v for k, v in detection.items() if k != "condition"})
    return found


def highlight(command: str, patterns: list[re.Pattern]) -> str:
    """The command line, escaped, with every span a rule pattern matches wrapped in <mark>."""
    spans = sorted((m.start(), m.end()) for p in patterns for m in p.finditer(command) if m.end() > m.start())
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out, pos = [], 0
    for start, end in merged:
        out.append(html.escape(command[pos:start]))
        out.append(f"<mark>{html.escape(command[start:end])}</mark>")
        pos = end
    out.append(html.escape(command[pos:]))
    return "".join(out)


def _verdict(event: Event, fired: bool) -> str:
    if event.label == "attack":
        return "<span class='ok'>✓ caught</span>" if fired else "<span class='bad'>✗ missed</span>"
    return "<span class='bad'>⚠ false alarm</span>" if fired else "<span class='ok'>✓ silent</span>"


_STYLE = """
<style>
.tb{width:100%;border-collapse:collapse;font-size:.86rem}
.tb td,.tb th{border-bottom:1px solid #1C2942;padding:.4rem .5rem;vertical-align:top;text-align:left}
.tb th{color:#9FB0CC;font-weight:600}
.tb .cmd{font-family:ui-monospace,Consolas,monospace;color:#E5ECF6;word-break:break-all}
.tb mark{background:#1D4ED8;color:#fff;border-radius:.2rem;padding:0 .1rem}
.tb .chip{background:#1A2847;color:#C7D3E6;border-radius:999px;padding:.1rem .5rem;font-size:.75rem;white-space:nowrap}
.tb .grp td{background:#111B30;color:#C7D3E6;font-weight:600}
.tb .ok{color:#4ADE80;white-space:nowrap}.tb .bad{color:#F87171;white-space:nowrap;font-weight:600}
</style>
"""


def grid(events: list[Event], rules: dict[str, tuple[str, set[str]]], changed_only: bool = False) -> str:
    """HTML: events grouped under their base attack; one verdict column per named rule.

    rules maps a column name ("before", "after") to (rule YAML, ids the harness says it fired on).
    The command is highlighted with the first rule's values. changed_only keeps rows where the rules
    disagree.
    """
    names = list(rules)
    first_patterns = rule_patterns(next(iter(rules.values()))[0]) if rules else []
    by_base: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_base[e.base_id].append(e)
    head = "".join(f"<th>{html.escape(n)}</th>" for n in names)
    rows = [f"{_STYLE}<table class='tb'><tr><th>disguise</th><th>command line</th>{head}</tr>"]
    shown = 0
    for base, group in by_base.items():
        group = sorted(group, key=lambda e: (e.transform != "none", e.transform))
        body = []
        for e in group:
            fired = [e.event_id in rules[n][1] for n in names]
            if changed_only and len(set(fired)) < 2:
                continue
            cells = "".join(f"<td>{_verdict(e, f)}</td>" for f in fired)
            kind = "original" if e.transform == "none" else e.transform
            body.append(
                f"<tr><td><span class='chip'>{html.escape(kind)}</span></td>"
                f"<td class='cmd'>{highlight(e.command_line, first_patterns)}</td>{cells}</tr>"
            )
        if body:
            label = "legitimate look-alike" if group[0].label == "benign" else "attack"
            rows.append(
                f"<tr class='grp'><td colspan='{2 + len(names)}'>{label} · {html.escape(base)}</td></tr>"
            )
            rows += body
            shown += len(body)
    if not shown:
        return "<p style='color:#9FB0CC'>No events to show here.</p>"
    return "".join(rows) + "</table>"
