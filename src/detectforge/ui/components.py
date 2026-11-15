"""Small display helpers shared by the UI tabs."""

import streamlit as st


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


def delta_pct(before: float | None, after: float | None) -> str | None:
    return None if before is None or after is None else f"{after - before:+.0%}"
