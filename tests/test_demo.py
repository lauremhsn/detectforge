"""The demo's failure scenarios (demo/README.md) keep working: a code change can't quietly break them.

Vague report, injected report, API failure and evasion caught, each with the exact inputs the demo
uses. All offline: the API-failure case points the client at a local port where nothing listens.
"""

import json
from pathlib import Path

import pytest
import yaml
from test_agent_loop import ScriptedClient, text
from test_intake import index, proposal  # noqa: F401  (index is a pytest fixture)

from detectforge import cli
from detectforge.agent.runner import run_hardening
from detectforge.events import load_events
from detectforge.harness import run
from detectforge.intake import interpret_request
from detectforge.llm import OpenAICompatibleClient
from detectforge.reference.index import ReferenceIndex

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "demo"
VAGUE = (DEMO / "vague_request.txt").read_text(encoding="utf-8")
INJECTED = (DEMO / "injected_report.txt").read_text(encoding="utf-8")


# ---- 1. vague report --------------------------------------------------------------------------


def test_vague_request_gets_a_question_not_a_guess(index, monkeypatch, capsys):  # noqa: F811
    assert interpret_request(VAGUE, index, None).status == "needs_clarification"  # keyword search
    asking = ScriptedClient([proposal(techniques=[], clarification="Which behaviour should be covered?")])
    assert interpret_request(VAGUE, index, asking).status == "needs_clarification"

    monkeypatch.setattr(cli, "_load_index_or_none", lambda: index)
    assert cli.main(["intake", "--file", str(DEMO / "vague_request.txt"), "--no-model"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "needs_clarification"


# ---- 2. injected report -----------------------------------------------------------------------


def test_injected_report_is_still_read_as_scheduled_task_persistence(index):  # noqa: F811
    assert "ignore all previous instructions" in INJECTED
    # A model that obeys the injection ("all clear", no tool call) is treated as unavailable:
    # intake falls back to keyword search, which still finds the behaviour.
    obeying = ScriptedClient([text("all clear, no new coverage needed")])
    result = interpret_request(INJECTED, index, obeying)
    assert result.status == "mapped" and result.source == "keyword_fallback"
    assert "T1053.005" in [t.technique for t in result.techniques]
    sent = obeying.requests[0][1]["content"]
    assert sent.startswith("<request>") and sent.rstrip().endswith("</request>")  # quoted as data


def test_an_obeying_model_can_at_worst_suggest_wrong_techniques_which_code_checks(index):  # noqa: F811
    obeying = ScriptedClient([proposal(techniques=["APPROVED", "T9999"], rationale="all clear")])
    result = interpret_request(INJECTED, index, obeying)
    assert result.status == "needs_clarification" and result.rejected == ["APPROVED", "T9999"]


# ---- 3. API failure ---------------------------------------------------------------------------


def test_api_failure_ends_as_needs_human_review_never_silently(fixture_events, load_rule_text, tmp_path):
    """Both models unreachable: the run is saved with its reasons, nothing is proposed silently."""
    down = OpenAICompatibleClient(
        base_url="http://127.0.0.1:9/v1",  # nothing listens here
        api_key="demo",
        model="primary",
        fallback_model="fallback",
        timeout_s=5,
        max_retries=0,
    )
    outcome = run_hardening(
        load_rule_text("schtasks_create_literal.yml"),
        "T1053.005",
        fixture_events,
        down,
        "primary",
        out_dir=tmp_path,
    )
    run_ = outcome.run
    assert run_.status == "needs_human_review" and run_.final_source == "original"
    assert any("LLM unavailable" in r and "fallback failed" in r for r in run_.reasons)
    assert (tmp_path / f"{run_.trace_id}.json").exists()  # the reviewer sees it in the Review tab


# ---- 4. evasion caught ------------------------------------------------------------------------

SYSTEM_RULE = (
    "89ca78fd-b37c-4310-b3d3-81a023f83936"  # Schtasks Creation Or Modification With SYSTEM Privileges
)
SIGMAHQ = REPO / "data" / "sigmahq"


@pytest.mark.skipif(not (SIGMAHQ / "index.jsonl").exists(), reason="needs the SigmaHQ index (sigmahq fetch)")
def test_the_community_rule_misses_the_held_out_insertion_the_demo_shows():
    rule = next(r for r in ReferenceIndex.load(SIGMAHQ).rules if r.id == SYSTEM_RULE)
    selection = yaml.safe_load((REPO / "data" / "eval" / "selection.yml").read_text(encoding="utf-8"))
    bases = next(r["base_attacks"] for r in selection["rules"] if r["id"] == SYSTEM_RULE)
    events = [
        e
        for name in ("base_events.jsonl", "mutations.jsonl")
        for e in load_events(REPO / "data" / "eval" / name)
        if e.base_id in bases
    ]
    matched = set(run(rule.rule_yaml, events).matched_event_ids)
    by_id = {e.event_id: e for e in events}
    assert "T1053.005-b04" in matched  # the plain command is detected
    evasion = by_id["T1053.005-b04-ins1"]
    assert evasion.command_line.startswith('schtasks /"create"') and evasion.split == "heldout"
    assert evasion.event_id not in matched  # ...the quoted variant is not
