"""Smoke tests: the UI renders and its numbers match the library on the fixture rules."""

import re
import shutil
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

from conftest import FIXTURES

APP = str(Path(__file__).resolve().parents[1] / "src" / "detectforge" / "ui" / "app.py")
REVIEWER_KEY = "test-key-0123456789abcdef"


def unescaped(markdown: str) -> str:
    """Table cells and untrusted text are backslash-escaped; tests read them as displayed."""
    return re.sub(r"\\(.)", r"\1", markdown)


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """A private data folder (fixtures copied in), so local runs or indexes never affect tests."""
    from detectforge import review

    data = tmp_path / "data"
    shutil.copytree(FIXTURES, data / "fixtures")
    monkeypatch.setenv("DETECTFORGE_DATA_DIR", str(data))
    monkeypatch.setenv("DETECTFORGE_UI_AUTO_FETCH_INDEX", "false")  # never hit the network in tests
    monkeypatch.setenv("DETECTFORGE_UI_ALLOW_AGENT_RUNS", "false")  # never inherit a local .env
    monkeypatch.setenv("DETECTFORGE_REVIEWER_KEYS", "")  # approving off unless a test sets keys
    review._failed.clear()
    return data


@pytest.fixture
def app(data_dir):
    from detectforge.config import get_settings

    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    yield at
    get_settings.cache_clear()


def test_renders_without_errors(app):
    assert not app.exception
    assert [t.label for t in app.tabs] == ["1 · Find", "2 · Validate", "3 · Harden", "4 · Review"]


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


def _saved_run(runs_dir, load_rule_text, fixture_events):
    """Create one real run file the way the CLI does, with a scripted model instead of an LLM."""
    from test_agent_loop import ScriptedClient, tool_call

    from detectforge.agent.runner import run_hardening

    original = load_rule_text("schtasks_create_literal.yml")
    robust = load_rule_text("schtasks_create_robust.yml")
    client = ScriptedClient(
        [
            tool_call("run_tuning_set", rule_yaml=robust),
            tool_call("submit", rule_yaml=robust, rationale="verb"),
        ]
    )
    return run_hardening(original, "T1053.005", fixture_events, client, "fake", out_dir=runs_dir)


def test_review_tab_without_runs_explains_how_to_get_one(app):
    assert any("No agent runs yet" in i.value for i in app.info)


def test_review_shows_a_run_and_records_approval(data_dir, load_rule_text, fixture_events, monkeypatch):
    from detectforge.config import get_settings
    from detectforge.review import decisions

    monkeypatch.setenv("DETECTFORGE_REVIEWER_KEYS", f"analyst:{REVIEWER_KEY}")
    outcome = _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception

    page = unescaped(" ".join(m.value for m in at.markdown))
    assert "pending review" in page and "33% → 100%" in page  # tuning before → after
    assert any(c.language == "diff" and "+    CommandLine|contains: 'create'" in c.value for c in at.code)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Held-out evasion resistance"] == "100%"

    approve = next(b for b in at.button if b.label == "Approve")
    approve.click().run()
    assert any("wrong reviewer key" in e.value for e in at.error)  # a key is required

    at.text_input(key="reviewer_key").set_value(REVIEWER_KEY).run()
    next(b for b in at.button if b.label == "Approve").click().run()
    assert any("Rule approved" in s.value for s in at.success)
    approved = data_dir / "runs" / "approved" / f"{outcome.run.trace_id}.yml"
    assert approved.read_text(encoding="utf-8") == outcome.run.final_rule_yaml
    # Recorded under the key's owner, and the key is not kept in the session after use.
    assert decisions(data_dir / "runs", outcome.run.trace_id)[-1].reviewer == "analyst"
    assert at.text_input(key="reviewer_key").value == ""


def test_review_warns_about_new_held_out_false_alarms(data_dir, load_rule_text, fixture_events):
    """The agent and gate never see held-out benign events, so the reviewer must be told."""
    import json

    from detectforge.config import get_settings

    outcome = _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    path = data_dir / "runs" / f"{outcome.run.trace_id}.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    saved["heldout_evaluation"]["new_false_alarm_event_ids"] = ["benign-reg-query"]
    saved["heldout_evaluation"]["false_alarms_after"] += 1
    path.write_text(json.dumps(saved), encoding="utf-8")

    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception
    assert any("1 new false alarm(s)" in e.value and "benign-reg-query" in e.value for e in at.error)
    assert "False alarms (held-out)" in {m.label for m in at.metric}


def test_injected_model_text_shows_literally_and_approving_is_off_without_keys(data_dir, fixture_events):
    """Security: a rationale with links, images or a fake 'approved' banner renders as plain text."""
    from test_agent_loop import ScriptedClient, tool_call
    from test_write_rule import WRITTEN

    from detectforge.agent.runner import run_writing
    from detectforge.config import get_settings

    hostile = (
        "**✅ APPROVED by the lead** [Approve now](https://evil.example/a) ![](https://evil.example/p.png)"
    )
    client = ScriptedClient([tool_call("submit", rule_yaml=WRITTEN, rationale=hostile)])
    run_writing("T1053.005", fixture_events, client, "fake", out_dir=data_dir / "runs")
    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception

    shown = [m.value for m in at.markdown if "evil" in m.value]
    assert shown and all("](https" not in v and "**✅" not in v for v in shown)
    assert any(hostile in unescaped(v) for v in shown)  # still readable, word for word
    assert all(b.disabled for b in at.button if b.label in ("Approve", "Reject"))
    assert any("Approving and rejecting are off here" in c.value for c in at.caption)


def test_review_shows_a_written_rule_as_new_not_as_a_change(data_dir, fixture_events):
    from test_agent_loop import ScriptedClient, tool_call
    from test_write_rule import WRITTEN

    from detectforge.agent.runner import run_writing
    from detectforge.config import get_settings

    client = ScriptedClient([tool_call("submit", rule_yaml=WRITTEN, rationale="behavior")])
    run_writing("T1053.005", fixture_events, client, "fake", out_dir=data_dir / "runs")
    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception

    page = " ".join(m.value for m in at.markdown)
    assert "**New rule**" in page and "What changed" not in page
    assert any(c.language == "yaml" and c.value.strip() == WRITTEN.strip() for c in at.code)
    assert any("wrote a new rule" in c.value for c in at.caption)
    assert {m.label: m.value for m in at.metric}["Held-out evasion resistance"] == "100%"


def test_agent_button_is_off_by_default(app):
    fixture = next(s for s in app.selectbox if s.label == "Fixture rule")
    fixture.set_value(fixture.options[0]).run()
    next(b for b in app.button if b.label == "Use fixture").click().run()
    button = next(b for b in app.button if b.label == "Ask the agent to harden this rule")
    assert button.disabled
    assert any("switched off" in c.value for c in app.caption)


def test_review_shows_the_agents_conversation(data_dir, load_rule_text, fixture_events):
    from detectforge.config import get_settings

    _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    toggle = next(t for t in at.toggle if t.label == "Show the agent's conversation")
    toggle.set_value(True).run()
    page = " ".join(m.value for m in at.markdown)
    assert "Instructions given to the agent" in page and "Step 1: the agent" in page
    assert "calls `run_tuning_set`" in page and "calls `submit`" in page
    assert any(c.language == "yaml" and "CommandLine|contains: 'create'" in c.value for c in at.code)


def test_old_runs_without_a_conversation_still_open(data_dir, load_rule_text, fixture_events):
    import json as _json

    from detectforge.config import get_settings

    outcome = _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    path = data_dir / "runs" / f"{outcome.run.trace_id}.json"
    saved = _json.loads(path.read_text(encoding="utf-8"))
    del saved["run"]["transcript"]
    path.write_text(_json.dumps(saved), encoding="utf-8")
    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    assert not at.exception
    assert any("saved before conversations were recorded" in c.value for c in at.caption)
