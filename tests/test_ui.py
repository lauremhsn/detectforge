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


def open_app(page: str = "coverage") -> AppTest:
    """Start the app on one area (as if picked in the top bar)."""
    from detectforge.config import get_settings

    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["page"] = page
    at.run()
    return at


@pytest.fixture
def app(data_dir):
    from detectforge.config import get_settings

    yield open_app()
    get_settings.cache_clear()


SECTIONS = ["home", "coverage", "request", "rules", "review", "reports", "operations", "settings"]


@pytest.mark.parametrize("page", SECTIONS)
def test_every_section_renders_and_says_what_it_is_for(data_dir, page):
    at = open_app(page)
    assert not at.exception
    menu = at.radio(key="page")  # the top bar, not the sidebar
    titles = ["Home", "Posture", "Threats", "Rules", "Review", "Reports", "Lab", "Settings"]
    assert [o.split("  (")[0] for o in menu.options] == titles
    assert menu.value == page
    assert at.query_params["page"] == page  # every area has its own shareable URL
    assert (at.title or page == "home") and at.caption  # each area opens with its name and purpose


def test_pipeline_status_shows_done_or_pending_only(data_dir):
    lab = open_app("operations")  # "About" lives in the Lab
    text = [m.value for m in lab.markdown]
    assert any("✅" in s for s in text) and any(s.endswith("— pending") for s in text)
    page_text = " ".join(e.value for e in [*lab.markdown, *lab.caption, *lab.sidebar.markdown])
    assert not re.search(r"\bW\d\b|\bweek\b", page_text, re.IGNORECASE)


def test_fixture_rule_flows_to_test_and_harden(data_dir):
    app = open_app("rules")
    fixture = next(s for s in app.selectbox if s.label == "Fixture rule")
    fixture.set_value(FIXTURES / "rules" / "schtasks_create_literal.yml").run()
    next(b for b in app.button if b.label == "Use fixture").click().run()
    assert app.radio(key="rules_step").value == "test"  # picking a rule moves on to testing it
    assert app.session_state["bench_technique"] == "T1053.005"  # tested on its own technique, no setting
    assert not app.exception

    metrics = [(m.label, m.value) for m in app.metric]
    assert ("Attacks detected", "2/5") in metrics  # validate tab
    assert ("Evasion resistance (mutations)", "25%") in metrics

    next(b for b in app.button if b.label == "Harden it →").click().run()
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


def test_review_queue_without_runs_explains_how_to_get_one(data_dir):
    assert any("No agent runs yet" in i.value for i in open_app("review").info)


def test_review_shows_a_run_and_records_approval(data_dir, load_rule_text, fixture_events, monkeypatch):
    from detectforge.config import get_settings
    from detectforge.review import decisions

    monkeypatch.setenv("DETECTFORGE_REVIEWER_KEYS", f"analyst:{REVIEWER_KEY}")
    outcome = _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    get_settings.cache_clear()
    at = open_app("review")
    assert not at.exception

    assert any("Ready for your decision" in s.value for s in at.success)  # the verdict comes first
    assert any(c.language == "diff" and "+    CommandLine|contains: 'create'" in c.value for c in at.code)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Unseen variations"] == "100%" and metrics["Tuning variations"] == "100%"
    assert metrics["New false alarms"] == "0"

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
    assert at.session_state["reviewer_key"] == ""


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
    at = open_app("review")
    assert not at.exception
    assert any("1 new false alarm(s)" in e.value and "benign-reg-query" in e.value for e in at.error)
    assert {m.label: m.value for m in at.metric}["New false alarms"] == "1"


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
    at = open_app("review")
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
    outcome = run_writing("T1053.005", fixture_events, client, "fake", out_dir=data_dir / "runs")
    get_settings.cache_clear()
    at = open_app("review")
    assert not at.exception

    page = " ".join(m.value for m in at.markdown)
    assert "**Written by the agent.**" in page and "What changed" not in page
    assert "were hidden from it" in page  # not "no community rule existed": in the write arm they're hidden
    shown = outcome.run.final_rule_yaml.strip()  # the written rule with its metadata stamped by code
    assert any(c.language == "yaml" and c.value.strip() == shown for c in at.code)
    assert any("Wrote a new rule" in c.value for c in at.caption)  # the found → changed → result story
    assert {m.label: m.value for m in at.metric}["Unseen variations"] == "100%"


def test_agent_button_is_off_by_default(data_dir):
    app = open_app("rules")
    fixture = next(s for s in app.selectbox if s.label == "Fixture rule")
    fixture.set_value(fixture.options[0]).run()
    next(b for b in app.button if b.label == "Use fixture").click().run()
    app.radio(key="rules_step").set_value("harden").run()
    button = next(b for b in app.button if b.label == "Ask the agent to harden this rule")
    assert button.disabled
    assert any("switched off" in c.value for c in app.caption)


def test_review_shows_the_agents_conversation(data_dir, load_rule_text, fixture_events):
    from detectforge.config import get_settings

    _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    get_settings.cache_clear()
    at = open_app("review")
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
    at = open_app("review")
    assert not at.exception
    assert any("saved before conversations were recorded" in c.value for c in at.caption)


def test_the_review_verdict_puts_what_matters_first(data_dir, load_rule_text, fixture_events):
    """One headline per situation, most important first; a decision already made is never 'pending'."""
    from datetime import UTC, datetime

    from detectforge.gate import GateCheck
    from detectforge.review import ReviewDecision
    from detectforge.ui.review_tab import verdict

    outcome = _saved_run(data_dir / "runs", load_rule_text, fixture_events)
    assert verdict(outcome, None).headline == "Ready for your decision"
    assert "100%" in verdict(outcome, None).text

    made = ReviewDecision(decision="approved", reviewer="**boss**", decided_at=datetime.now(UTC))
    approved = verdict(outcome, made)
    assert (approved.kind, approved.headline) == ("success", "Approved")
    assert r"\*\*boss\*\*" in approved.text  # a reviewer name is shown literally
    rejected = verdict(outcome, made.model_copy(update={"decision": "rejected"}))
    assert (rejected.kind, rejected.headline) == ("info", "Rejected")

    heldout = outcome.heldout_evaluation.model_copy(update={"new_false_alarm_event_ids": ["benign-x"]})
    noisy = outcome.model_copy(update={"heldout_evaluation": heldout})
    assert (verdict(noisy, None).kind, verdict(noisy, None).headline) == ("error", "Check before approving")

    failed_gate = outcome.run.gate.model_copy(
        update={"passed": False, "checks": [GateCheck(name="no_lost_attacks", passed=False, detail="1")]}
    )
    failing = outcome.model_copy(update={"run": outcome.run.model_copy(update={"gate": failed_gate})})
    assert verdict(failing, None).headline == "Needs your judgement"
    assert "no lost attacks" in verdict(failing, None).text

    empty = outcome.model_copy(update={"run": outcome.run.model_copy(update={"final_rule_yaml": ""})})
    assert verdict(empty, None).headline == "Nothing to approve"


def test_a_rule_firing_on_everyday_commands_outside_the_data_must_be_checked(data_dir):
    from detectforge.ui.lookalikes import Lookalike, firing_lookalikes

    reg_query = Lookalike(
        id="x1", technique="T1003.002", binary="reg.exe", why="reads a value", cmd=r"reg query HKLM\SYSTEM\X"
    )
    base = "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
    image = "  sel:\n    Image|endswith: '" + "\\" + "reg.exe'\n"
    broad = base + image + "    CommandLine|contains: 'hklm'\n  condition: sel\n"
    precise = base + image + "    CommandLine|contains: ' save '\n  condition: sel\n"
    assert [x.id for x in firing_lookalikes(broad, [reg_query])] == ["x1"]
    assert firing_lookalikes(precise, [reg_query]) == []


def test_posture_shows_the_approved_version_not_the_newest_rejected_one():
    from detectforge.ui.coverage_page import RunCell, _in_use

    def cell(decision: str, after: float) -> RunCell:
        return RunCell(
            status="passed", heldout_before=0, heldout_after=after, heldout_mutations=2, decision=decision
        )

    newest_first = [cell("rejected", 1.0), cell("approved", 0.5), cell("pending review", 0.7)]
    assert _in_use(newest_first).decision == "approved"
    assert _in_use([cell("rejected", 1.0), cell("pending review", 0.7)]).decision == "pending review"
    assert _in_use([cell("rejected", 1.0)]).decision == "rejected"  # labelled as rejected on the card


def test_rationale_points_keep_structure_but_never_render_links():
    from detectforge.ui.review_visuals import rationale_points

    text = (
        "The rule watches three tools:\n1.\n**vssadmin.exe** - deletes `delete shadows /all`.\n"
        "2.\nSee [approved](https://evil.example) ![x](https://evil.example/a.png)"
    )
    points = rationale_points(text)
    assert points[0].startswith("The rule watches three tools") and "vssadmin" in points[0]  # "1." gone
    assert "**" not in points[0]  # bold stays literal (escaped): model text can't look like a banner
    assert "`delete shadows /all`" in points[0]  # inline code shown as written
    assert all("](" not in p for p in points)  # no link or image can render


def test_testbench_highlights_what_the_rule_looks_for_and_escapes_everything():
    from detectforge.ui.testbench import highlight, rule_patterns

    rule = "detection:\n  sel:\n    CommandLine|contains: ' /create '\n  condition: sel\n"
    shown = highlight('schtasks /CREATE /tn "<b>x</b>"', rule_patterns(rule))
    assert "<mark> /CREATE </mark>" in shown  # case-insensitive, like Windows and Sigma
    assert "<b>" not in shown and "&lt;b&gt;" in shown  # command lines are untrusted: escaped
    assert highlight("schtasks /cre­ate", rule_patterns(rule)).count("<mark>") == 0  # the disguise breaks it
