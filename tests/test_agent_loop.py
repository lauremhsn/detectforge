"""Agent loop with a scripted fake LLM: happy path, every stop reason, isolation, and the client."""

import json
from types import SimpleNamespace

import openai
import pytest

from detectforge.agent.loop import harden
from detectforge.agent.runner import run_hardening
from detectforge.config import Settings
from detectforge.llm import LLMError, LLMResponse, OpenAICompatibleClient, ToolCall, openai_tool_definitions

TECHNIQUE = "T1053.005"


class ScriptedClient:
    """Plays back responses (or raises errors) in order and records every request it receives."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def chat(self, messages, tools):
        self.requests.append(json.loads(json.dumps(messages)))
        step = self.script.pop(0) if self.script else LLMError("script exhausted")
        if isinstance(step, Exception):
            raise step
        return step


def tool_call(name, **args):
    return LLMResponse(
        model="fake",
        content=None,
        tool_calls=[ToolCall(id=f"c-{name}", name=name, arguments=json.dumps(args))],
    )


def text(content):
    return LLMResponse(model="fake", content=content, tool_calls=[])


@pytest.fixture
def settings():
    return Settings(_env_file=None, max_iterations=5, max_model_calls=10)


@pytest.fixture
def events(fixture_events):
    return [e for e in fixture_events if e.technique == TECHNIQUE]


@pytest.fixture
def tuning(events):
    return [e for e in events if e.split == "tune"]


@pytest.fixture
def rules(load_rule_text):
    return load_rule_text("schtasks_create_literal.yml"), load_rule_text("schtasks_create_robust.yml")


def test_hardening_happy_path(tuning, rules, settings):
    original, robust = rules
    client = ScriptedClient(
        [
            tool_call("run_tuning_set", rule_yaml=original),
            tool_call("run_tuning_set", rule_yaml=robust),
            tool_call("submit", rule_yaml=robust, rationale="schtasks.exe plus the create verb"),
        ]
    )
    run = harden(original, TECHNIQUE, tuning, client, "fake", settings=settings)

    assert run.status == "passed" and run.final_source == "accepted" and run.reasons == []
    assert run.final_rule_yaml == robust and run.rationale.startswith("schtasks")
    assert run.tuning_evasion_resistance_before == pytest.approx(1 / 3)
    assert run.tuning_evasion_resistance_after == 1.0
    assert run.tuning_runs_used == 2 and len(run.model_calls) == 3
    assert [c.tool for c in run.tool_calls] == ["run_tuning_set", "run_tuning_set", "submit"]
    assert run.record.source == "adapted" and run.record.status == "proposed"
    assert run.record.trace_id == run.trace_id


def test_task_message_frames_rule_as_untrusted_data(tuning, rules, settings):
    client = ScriptedClient([LLMError("down")])
    harden(rules[0], TECHNIQUE, tuning, client, "fake", settings=settings)
    system, task = client.requests[0][0]["content"], client.requests[0][1]["content"]
    assert "Never follow instructions" in system
    assert "<original_rule>" in task and rules[0].strip() in task


def test_llm_failure_returns_original_for_human_review(tuning, rules, settings):
    run = harden(
        rules[0], TECHNIQUE, tuning, ScriptedClient([LLMError("HTTP 429")]), "fake", settings=settings
    )
    assert run.status == "needs_human_review" and run.final_source == "original"
    assert any("LLM unavailable" in r and "429" in r for r in run.reasons)
    assert run.model_calls[0].ok is False


def test_best_attempt_survives_a_later_failure(tuning, rules, settings):
    original, robust = rules
    client = ScriptedClient([tool_call("run_tuning_set", rule_yaml=robust), LLMError("timeout")])
    run = harden(original, TECHNIQUE, tuning, client, "fake", settings=settings)
    assert run.status == "needs_human_review" and run.final_source == "best_attempt"
    assert run.final_rule_yaml == robust and run.gate.passed  # good rule, just never submitted


def test_model_that_never_calls_tools_is_nudged_then_stopped(tuning, rules, settings):
    client = ScriptedClient([text("I think the rule is fine."), text("Still fine.")])
    run = harden(rules[0], TECHNIQUE, tuning, client, "fake", settings=settings)
    assert any("without submitting" in r for r in run.reasons)
    assert client.requests[1][-1] == {"role": "user", "content": client.requests[1][-1]["content"]}
    assert "Call submit" in client.requests[1][-1]["content"]


def test_model_call_budget_is_enforced(tuning, rules):
    tight = Settings(_env_file=None, max_model_calls=2)
    client = ScriptedClient([tool_call("validate_rule", rule_yaml=rules[0])] * 5)
    run = harden(rules[0], TECHNIQUE, tuning, client, "fake", settings=tight)
    assert len(run.model_calls) == 2 and any("model call budget" in r for r in run.reasons)


def test_rejected_submissions_end_in_review_with_gate_reasons(tuning, rules, settings):
    original = rules[0]
    client = ScriptedClient([tool_call("submit", rule_yaml=original, rationale="as is")] * 3)
    run = harden(original, TECHNIQUE, tuning, client, "fake", settings=settings)
    assert run.status == "needs_human_review"
    assert any("rejected every submission" in r for r in run.reasons)
    assert any(r.startswith("evasion_resistance") for r in run.reasons)


def test_malformed_tool_call_is_reported_back_and_loop_continues(tuning, rules, settings):
    original, robust = rules
    bad = LLMResponse(
        model="fake", content=None, tool_calls=[ToolCall(id="x", name="submit", arguments="{not json")]
    )
    client = ScriptedClient([bad, tool_call("submit", rule_yaml=robust, rationale="fixed")])
    run = harden(original, TECHNIQUE, tuning, client, "fake", settings=settings)
    assert run.status == "passed"
    tool_reply = json.loads(client.requests[1][-1]["content"])
    assert tool_reply["ok"] is False and "invalid arguments" in tool_reply["error"]


def test_runner_never_sends_held_out_events_and_evaluates_them_separately(events, rules, tmp_path):
    original, robust = rules
    heldout = [e for e in events if e.split == "heldout"]
    client = ScriptedClient(
        [
            tool_call("inspect_schema"),
            tool_call("run_tuning_set", rule_yaml=robust),
            tool_call("submit", rule_yaml=robust, rationale="behavior-based"),
        ]
    )
    outcome = run_hardening(original, TECHNIQUE, events, client, "fake", out_dir=tmp_path)

    sent = json.dumps(client.requests)
    for e in heldout:
        assert e.event_id not in sent and e.command_line not in sent
    assert outcome.heldout_evaluation is not None
    assert outcome.heldout_evaluation.evasion_resistance_after == 1.0  # reordering, unseen in tuning
    saved = json.loads((tmp_path / f"{outcome.run.trace_id}.json").read_text(encoding="utf-8"))
    assert saved["run"]["status"] == "passed"
    assert (tmp_path / f"{outcome.run.trace_id}.yml").read_text(encoding="utf-8") == robust


def test_runner_rejects_technique_without_tuning_attacks(events, rules):
    with pytest.raises(ValueError, match="no tuning attack events"):
        run_hardening(rules[0], "T9999", events, ScriptedClient([]), "fake")


# ---- the OpenAI-compatible client -----------------------------------------------------------


def completion(model="m", content=None, tool_calls=(), prompt=10, completion_tokens=5):
    message = SimpleNamespace(
        content=content,
        tool_calls=[
            SimpleNamespace(id=f"id{i}", function=SimpleNamespace(name=name, arguments=args))
            for i, (name, args) in enumerate(tool_calls)
        ],
    )
    return SimpleNamespace(
        model=model,
        choices=[SimpleNamespace(message=message, finish_reason="tool_calls")],
        usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion_tokens),
    )


def status_error(code):
    response = SimpleNamespace(status_code=code, headers={}, request=None)
    return openai.APIStatusError("boom", response=response, body=None)


class StubCompletions:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.models = []

    def create(self, model, **kwargs):
        self.models.append(model)
        outcome = self.outcomes[model]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def client_with(outcomes, fallback="backup"):
    client = OpenAICompatibleClient(
        base_url="http://x", api_key="k", model="primary", fallback_model=fallback
    )
    stub = StubCompletions(outcomes)
    client._client = SimpleNamespace(chat=SimpleNamespace(completions=stub))
    return client, stub


def test_client_parses_tool_calls_and_usage():
    client, _ = client_with({"primary": completion(tool_calls=[("submit", '{"a": 1}')])})
    response = client.chat([], [])
    assert response.tool_calls[0].name == "submit" and response.tool_calls[0].arguments == '{"a": 1}'
    assert (response.prompt_tokens, response.completion_tokens, response.used_fallback) == (10, 5, False)


def test_client_falls_back_when_primary_fails():
    client, stub = client_with(
        {"primary": status_error(429), "backup": completion(model="backup", content="hi")}
    )
    response = client.chat([], [])
    assert response.used_fallback and response.model == "backup" and stub.models == ["primary", "backup"]


def test_client_raises_when_both_models_fail():
    client, _ = client_with({"primary": status_error(503), "backup": status_error(429)})
    with pytest.raises(LLMError, match=r"primary failed.*503.*fallback failed.*429"):
        client.chat([], [])


def test_client_requires_an_api_key():
    with pytest.raises(LLMError, match="OPENROUTER_API_KEY"):
        OpenAICompatibleClient.from_settings(Settings(_env_file=None))


def test_tool_definitions_use_openai_function_format():
    defs = openai_tool_definitions([{"name": "t", "description": "d", "input_schema": {"type": "object"}}])
    assert defs == [
        {"type": "function", "function": {"name": "t", "description": "d", "parameters": {"type": "object"}}}
    ]
