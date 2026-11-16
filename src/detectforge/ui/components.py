"""Small display helpers shared by the UI tabs."""

import re

import streamlit as st


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
