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


# Fixed styling written here (never built from data), so it carries no injection risk.
_STYLE = """
<style>
[data-testid="stMetric"] {
  background: var(--df-card, #131D33); border: 1px solid #22304D; border-radius: 0.75rem;
  padding: 0.9rem 1.1rem;
}
[data-testid="stMetricValue"] { font-weight: 650; font-variant-numeric: tabular-nums; }
[data-testid="stMetricLabel"] p { color: #9FB0CC; font-size: 0.85rem; }
[data-testid="stMarkdownContainer"] table {
  width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.9rem;
  border: 1px solid #22304D; border-radius: 0.6rem; overflow: hidden;
}
[data-testid="stMarkdownContainer"] th {
  background: #16223A; color: #C7D3E6; font-weight: 600; text-align: left;
}
[data-testid="stMarkdownContainer"] td, [data-testid="stMarkdownContainer"] th {
  border: none; border-bottom: 1px solid #1C2942; padding: 0.5rem 0.75rem;
  font-variant-numeric: tabular-nums;
}
[data-testid="stMarkdownContainer"] tr:last-child td { border-bottom: none; }
[data-testid="stMarkdownContainer"] tbody tr:hover { background: #111B30; }
section[data-testid="stSidebar"] [role="radiogroup"] label { padding: 0.25rem 0; }
.block-container { padding-top: 2.2rem; max-width: 1300px; }
</style>
"""


def apply_style() -> None:
    st.markdown(_STYLE, unsafe_allow_html=True)
