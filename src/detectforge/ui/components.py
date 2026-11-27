"""Small display helpers shared by the UI tabs."""

import re

import streamlit as st
import yaml

from detectforge.rules.convert import convert_rule
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


def rule_title(rule_yaml: str, fallback: str) -> str:
    """The rule's own title (SigmaHQ or model text: escape it with md() before rendering)."""
    try:
        title = (yaml.safe_load(rule_yaml or "") or {}).get("title")
    except (yaml.YAMLError, AttributeError):
        return fallback
    return str(title).strip() if title else fallback


def delta_pct(before: float | None, after: float | None) -> str | None:
    return None if before is None or after is None else f"{after - before:+.0%}"


def export_view(rule_yaml: str, name: str) -> None:
    """Download the rule as Sigma YAML or as a ready-to-paste Elastic query."""
    with st.expander("Export (Sigma YAML or an Elastic query)"):
        st.download_button("Download Sigma YAML", rule_yaml, file_name=f"{name}.yml", key=f"dl_yaml_{name}")
        target = st.radio("Elastic query language", ["eql", "lucene"], horizontal=True, key=f"target_{name}")
        st.caption(
            "Sigma is the vendor-neutral format; a SIEM runs its own query language. **EQL** (Event Query "
            "Language) is recommended: tested in a real Elasticsearch, it fires on exactly the same events "
            "as DetectForge for every community rule. **Lucene** matches command lines case-sensitively, "
            "so a different letter case (HKLM vs hklm) slips past it. A rule with regular expressions may "
            "need adjusting: Elastic's regex dialect has no (?i) or word boundaries."
        )
        try:
            query = "\n".join(convert_rule(rule_yaml, target))
        except (RuleError, ValueError) as e:
            st.caption(f"Can't convert this rule: {md(e)}")
            return
        st.code(query, language=None, wrap_lines=True)


# Fixed styling written here (never built from data), so it carries no injection risk.
_STYLE = """
<style>
[data-testid="stMetric"] {
  background: var(--df-card, #FBF9F6); border: 1px solid #D8D1C6; border-radius: 0.75rem;
  padding: 0.9rem 1.1rem;
}
[data-testid="stMetricValue"] { font-weight: 650; font-variant-numeric: tabular-nums; }
[data-testid="stMetricLabel"] p { color: #5B5348; font-size: 0.85rem; }
[data-testid="stMarkdownContainer"] table {
  width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.9rem;
  border: 1px solid #D8D1C6; border-radius: 0.6rem; overflow: hidden;
}
[data-testid="stMarkdownContainer"] th {
  background: #EAE5DD; color: #2A2622; font-weight: 600; text-align: left;
}
[data-testid="stMarkdownContainer"] td, [data-testid="stMarkdownContainer"] th {
  border: none; border-bottom: 1px solid #E3DDD3; padding: 0.5rem 0.75rem;
  font-variant-numeric: tabular-nums;
}
[data-testid="stMarkdownContainer"] tr:last-child td { border-bottom: none; }
[data-testid="stMarkdownContainer"] tbody tr:hover { background: #EFEAE2; }
.block-container { padding-top: 3.6rem; max-width: 1300px; }
h1 { font-size: 1.9rem !important; padding-top: 0.4rem !important; }

/* Radios drawn as tabs (top bar) or as list rows (review inbox); still radios underneath, so they
   stay keyboard-accessible. Streamlit 1.67 markup: label[data-testid=stRadioOption][data-selected]. */
.st-key-topbar label[data-testid="stRadioOption"] > div > div:not([data-testid="stMarkdownContainer"]),
.st-key-inbox label[data-testid="stRadioOption"] > div > div:not([data-testid="stMarkdownContainer"]) {
  display: none;
}

.st-key-topbar {
  padding-bottom: 0.5rem; border-bottom: 3px solid transparent;
  border-image: linear-gradient(90deg, #C2551F, #3D5A73) 1;
}
.st-key-topbar [role="radiogroup"] { gap: 0.2rem; justify-content: flex-end; flex-wrap: wrap; }
@media (max-width: 640px) { .st-key-topbar [role="radiogroup"] { justify-content: flex-start; } }
.st-key-topbar label[data-testid="stRadioOption"] {
  padding: 0.4rem 0.95rem; margin: 0; border-radius: 0.5rem; cursor: pointer;
}
.st-key-topbar label[data-testid="stRadioOption"] p { color: #5B5348; font-weight: 500; }
.st-key-topbar label[data-testid="stRadioOption"]:hover { background: #EFEAE2; }
.st-key-topbar label[data-testid="stRadioOption"][data-selected="true"] { background: #F6E4D8; }
.st-key-topbar label[data-testid="stRadioOption"][data-selected="true"] p {
  color: #1F2328; font-weight: 650;
}

.st-key-stepper label[data-testid="stRadioOption"] > div > div:not([data-testid="stMarkdownContainer"]) {
  display: none;
}
.st-key-stepper [role="radiogroup"] { gap: 0.4rem; }
.st-key-stepper label[data-testid="stRadioOption"] {
  padding: 0.45rem 1rem; margin: 0; border-radius: 999px; cursor: pointer; border: 1px solid #D8D1C6;
}
.st-key-stepper label[data-testid="stRadioOption"] p { color: #5B5348; font-weight: 500; }
.st-key-stepper label[data-testid="stRadioOption"][data-selected="true"] {
  background: #C2551F; border-color: #C2551F;
}
.st-key-stepper label[data-testid="stRadioOption"][data-selected="true"] p { color: #FFFFFF; }

.st-key-inbox [role="radiogroup"] { gap: 0; width: 100%; }
.st-key-inbox [role="radiogroup"] > div {
  width: 100%; padding: 0.7rem 0.85rem; cursor: pointer;
  border-bottom: 1px solid #E3DDD3; border-left: 3px solid transparent;
}
.st-key-inbox [role="radiogroup"] > div:hover { background: #EFEAE2; }
.st-key-inbox [role="radiogroup"] > div[data-selected="true"] {
  background: #FBF9F6; border-left-color: #C2551F;
}
.st-key-inbox label[data-testid="stRadioOption"] { margin: 0; padding: 0; }
.st-key-inbox label[data-testid="stRadioOption"] p { font-weight: 600; }
</style>
"""


def apply_style() -> None:
    st.markdown(_STYLE, unsafe_allow_html=True)
