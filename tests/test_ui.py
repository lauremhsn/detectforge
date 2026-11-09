"""Smoke tests: the UI renders and its numbers match the library on the fixture rules."""

import re
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

from conftest import FIXTURES

APP = str(Path(__file__).resolve().parents[1] / "src" / "detectforge" / "ui" / "app.py")


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("DETECTFORGE_DATA_DIR", str(FIXTURES.parent))
    monkeypatch.setenv("DETECTFORGE_UI_AUTO_FETCH_INDEX", "false")  # never hit the network in tests
    from detectforge.config import get_settings

    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    yield at
    get_settings.cache_clear()


def test_renders_without_errors(app):
    assert not app.exception
    assert [t.label for t in app.tabs] == ["1 · Find", "2 · Validate", "3 · Harden"]


def test_pipeline_status_shows_done_or_pending_only(app):
    sidebar = [m.value for m in app.sidebar.markdown]
    assert any("✅" in s for s in sidebar) and any(s.endswith("— pending") for s in sidebar)
    page_text = " ".join(e.value for e in [*app.markdown, *app.caption, *app.sidebar.markdown])
    assert not re.search(r"\bW\d\b|\bweek\b", page_text, re.IGNORECASE)


def test_fixture_rule_flows_to_validate_and_harden(app):
    fixture = next(s for s in app.selectbox if s.label == "Fixture rule")
    fixture.set_value(FIXTURES / "rules" / "schtasks_create_literal.yml").run()
    next(b for b in app.button if b.label == "Use fixture").click().run()
    app.sidebar.selectbox[0].set_value("T1053.005").run()
    assert not app.exception

    metrics = [(m.label, m.value) for m in app.metric]
    assert ("Attacks detected", "2/5") in metrics  # validate tab
    assert ("Evasion resistance (mutations)", "25%") in metrics

    robust = (FIXTURES / "rules" / "schtasks_create_robust.yml").read_text(encoding="utf-8")
    app.text_area(key="after_editor").set_value(robust).run()
    assert ("Evasion resistance", "100%") in [(m.label, m.value) for m in app.metric]
    assert any("Newly detected attacks" in s.value for s in app.success)


def test_cloud_requirements_match_pyproject():
    """Streamlit Cloud installs from ui/requirements.txt, so it must list the same dependencies."""
    import tomllib

    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    expected = {*pyproject["project"]["dependencies"], *pyproject["dependency-groups"]["ui"]}
    lines = (root / "src" / "detectforge" / "ui" / "requirements.txt").read_text(encoding="utf-8")
    actual = {line.strip() for line in lines.splitlines() if line.strip() and not line.startswith("#")}
    assert actual == expected
