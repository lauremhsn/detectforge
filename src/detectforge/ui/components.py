"""Small display helpers shared by the UI tabs."""

import re

import streamlit as st

from detectforge.rules.convert import TARGETS, convert_rule
from detectforge.rules.parse import RuleError


def table(rows: list[dict]) -> None:
    """Render rows as a markdown table (st.dataframe needs pandas, which some machines block)."""
    if not rows:
        return
    cols = list(rows[0])
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(_cell(r[c]) for c in cols) + " |" for r in rows]
    st.markdown("\n".join(lines))


_PUNCTUATION = re.compile(r"([!-/:-@\[-`{-~])")


def md(text: object) -> str:
    """Untrusted text (model output, SigmaHQ fields, command lines) made safe for st.markdown.

    Every ASCII punctuation character is backslash-escaped, which CommonMark renders as itself. So
    the text shows exactly as written: no links or images a reviewer might click or load, no headings
    or bold that could pass for DetectForge's own messages, no Streamlit colour or icon directives.
    """
    return _PUNCTUATION.sub(r"\\\1", str(text))


def _cell(value: object) -> str:
    return md(str(value).replace("\n", " "))


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def delta_pct(before: float | None, after: float | None) -> str | None:
    return None if before is None or after is None else f"{after - before:+.0%}"


def export_view(rule_yaml: str, name: str) -> None:
    """Download the rule as Sigma YAML or as a ready-to-paste Elastic query."""
    with st.expander("Export (Sigma YAML or an Elastic query)"):
        st.download_button("Download Sigma YAML", rule_yaml, file_name=f"{name}.yml", key=f"dl_yaml_{name}")
        target = st.radio("Elastic query language", sorted(TARGETS), horizontal=True, key=f"target_{name}")
        try:
            query = "\n".join(convert_rule(rule_yaml, target))
        except (RuleError, ValueError) as e:
            st.caption(f"Can't convert this rule: {md(e)}")
            return
        st.code(query, language=None)
