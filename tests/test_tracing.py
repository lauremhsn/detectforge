"""Tracing: what a run records, that held-out data never leaves, and that tracing can't break runs."""

import json
from contextlib import contextmanager

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from test_agent_loop import TECHNIQUE, ScriptedClient, tool_call

from detectforge.agent.loop import harden
from detectforge.agent.runner import run_hardening
from detectforge.config import Settings
from detectforge.llm import LLMError
from detectforge.tracing import LangfuseTracer, NoopTracer, make_tracer

# ---- a tracer that records observations in memory ------------------------------------------


class RecordingTracer:
    def __init__(self):
        self.observations = []
        self._stack = []
        self.flushed = False

    @contextmanager
    def observe(self, name, kind, trace_id=None, **fields):
        record = {
            "name": name,
            "kind": kind,
            "trace_id": trace_id,
            "parent": self._stack[-1]["name"] if self._stack else None,
            "fields": fields,
            "updates": {},
        }
        self.observations.append(record)
        self._stack.append(record)
        try:
            yield _Updater(record)
        finally:
            self._stack.pop()

    def trace_url(self, trace_id):
        return f"https://traces.example/{trace_id}"

    def flush(self):
        self.flushed = True

    def named(self, prefix):
        return [o for o in self.observations if o["name"].startswith(prefix)]


class _Updater:
    def __init__(self, record):
        self.record = record

    def update(self, **fields):
        self.record["updates"].update(fields)


@pytest.fixture
def settings():
    return Settings(_env_file=None, max_model_calls=10)


@pytest.fixture
def events(fixture_events):
    return [e for e in fixture_events if e.technique == TECHNIQUE]


@pytest.fixture
def rules(load_rule_text):
    return load_rule_text("schtasks_create_literal.yml"), load_rule_text("schtasks_create_robust.yml")


def test_run_is_one_trace_with_a_child_per_model_and_tool_call(events, rules, settings):
    original, robust = rules
    tuning = [e for e in events if e.split == "tune"]
    tracer = RecordingTracer()
    client = ScriptedClient(
        [tool_call("run_tuning_set", rule_yaml=robust), tool_call("submit", rule_yaml=robust, rationale="x")]
    )
    run = harden(original, TECHNIQUE, tuning, client, "fake", settings=settings, tracer=tracer)

    root = tracer.observations[0]
    assert (root["name"], root["kind"], root["trace_id"]) == ("harden", "agent", run.trace_id)
    assert root["fields"]["metadata"]["prompt_version"] == run.prompt_version
    assert root["updates"]["output"]["status"] == "passed"
    assert [(o["name"], o["kind"]) for o in tracer.observations[1:]] == [
        ("llm", "generation"),
        ("tool:run_tuning_set", "tool"),
        ("llm", "generation"),
        ("tool:submit", "tool"),
    ]
    assert all(o["parent"] == "harden" for o in tracer.observations[1:])
    generation = tracer.named("llm")[0]
    assert generation["updates"]["usage_details"] == {"input": 0, "output": 0}
    assert generation["updates"]["output"]["tool_calls"][0]["name"] == "run_tuning_set"


def test_failures_are_marked_in_the_trace(events, rules, settings):
    tuning = [e for e in events if e.split == "tune"]
    tracer = RecordingTracer()
    client = ScriptedClient([tool_call("deploy_rule"), LLMError("HTTP 429")])
    run = harden(rules[0], TECHNIQUE, tuning, client, "fake", settings=settings, tracer=tracer)

    assert tracer.named("tool:deploy_rule")[0]["updates"]["level"] == "ERROR"
    failed_llm = tracer.named("llm")[-1]["updates"]
    assert failed_llm["level"] == "ERROR" and "429" in failed_llm["status_message"]
    gate = tracer.named("quality_gate")[0]
    assert gate["kind"] == "evaluator" and gate["parent"] == "harden"
    assert tracer.observations[0]["updates"]["level"] == "WARNING"
    assert run.status == "needs_human_review"


def test_held_out_events_never_reach_the_tracer(events, rules, tmp_path):
    original, robust = rules
    heldout = [e for e in events if e.split == "heldout"]
    tracer = RecordingTracer()
    client = ScriptedClient(
        [
            tool_call("inspect_schema"),
            tool_call("run_tuning_set", rule_yaml=robust),
            tool_call("submit", rule_yaml=robust, rationale="x"),
        ]
    )
    outcome = run_hardening(original, TECHNIQUE, events, client, "fake", tracer=tracer)

    traced = json.dumps(tracer.observations, default=str)
    for e in heldout:
        assert e.event_id not in traced and e.command_line not in traced
    assert outcome.heldout_evaluation is not None  # computed, but outside the trace
    assert tracer.flushed and outcome.trace_url.endswith(outcome.run.trace_id)


# ---- the Langfuse tracer --------------------------------------------------------------------


@pytest.fixture
def exporter():
    from langfuse import Langfuse

    spans = InMemorySpanExporter()
    client = Langfuse(
        public_key="pk-lf-test", secret_key="sk-lf-test", base_url="http://127.0.0.1:9", span_exporter=spans
    )
    return spans, LangfuseTracer(client)


def test_langfuse_tracer_exports_nested_typed_spans(exporter):
    spans, tracer = exporter
    trace_id = "ab" * 16
    with tracer.observe("harden", "agent", trace_id=trace_id) as root:
        with tracer.observe("llm", "generation", model="m", input=[{"role": "user", "content": "hi"}]) as gen:
            gen.update(usage_details={"input": 3, "output": 4})
        with tracer.observe("tool:submit", "tool") as tool:
            tool.update(level="ERROR", status_message="bad")
        root.update(output={"status": "passed"})
    tracer.flush()

    by_name = {s.name: s for s in spans.get_finished_spans()}
    assert set(by_name) == {"harden", "llm", "tool:submit"}
    assert all(format(s.context.trace_id, "032x") == trace_id for s in by_name.values())
    assert by_name["llm"].parent.span_id == by_name["harden"].context.span_id
    assert by_name["llm"].attributes["langfuse.observation.type"] == "generation"
    assert json.loads(by_name["llm"].attributes["langfuse.observation.usage_details"]) == {
        "input": 3,
        "output": 4,
    }
    assert by_name["tool:submit"].attributes["langfuse.observation.level"] == "ERROR"


class _BrokenClient:
    """Every Langfuse call fails, the way a misconfigured or unreachable backend might."""

    def start_as_current_observation(self, **kwargs):
        raise RuntimeError("backend down")

    def get_trace_url(self, trace_id):
        raise RuntimeError("backend down")

    def flush(self):
        raise RuntimeError("backend down")


class _FlakyObservationClient:
    def __init__(self):
        self.exited_with = []

    @contextmanager
    def _manager(self):
        class Obs:
            def update(self, **fields):
                raise RuntimeError("update failed")

        try:
            yield Obs()
        except BaseException as e:
            self.exited_with.append(type(e).__name__)
            raise

    def start_as_current_observation(self, **kwargs):
        return self._manager()


def test_broken_backend_never_breaks_a_run(events, rules, settings):
    tuning = [e for e in events if e.split == "tune"]
    tracer = LangfuseTracer(_BrokenClient())
    client = ScriptedClient([tool_call("submit", rule_yaml=rules[1], rationale="x")])
    run = harden(rules[0], TECHNIQUE, tuning, client, "fake", settings=settings, tracer=tracer)
    assert run.status == "passed"
    assert tracer.trace_url(run.trace_id) is None
    tracer.flush()  # swallowed


def test_tracer_swallows_its_own_errors_but_not_the_runs():
    flaky = _FlakyObservationClient()
    tracer = LangfuseTracer(flaky)
    with tracer.observe("x", "span") as obs:
        obs.update(output=1)  # swallowed
    with pytest.raises(ValueError, match="real bug"), tracer.observe("y", "span"):
        raise ValueError("real bug")
    assert flaky.exited_with == ["ValueError"]


@pytest.mark.parametrize(
    "keys",
    [{}, {"LANGFUSE_PUBLIC_KEY": "pk"}, {"LANGFUSE_PUBLIC_KEY": " ", "LANGFUSE_SECRET_KEY": " "}],
    ids=["no-keys", "one-key", "blank-keys"],
)
def test_tracing_is_off_without_both_keys(monkeypatch, keys):
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in keys.items():
        monkeypatch.setenv(name, value)
    assert isinstance(make_tracer(Settings(_env_file=None)), NoopTracer)


def test_tracing_falls_back_to_noop_if_langfuse_cannot_start(monkeypatch):
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")

    def boom(settings):
        raise RuntimeError("cannot start")

    monkeypatch.setattr(LangfuseTracer, "from_settings", classmethod(lambda cls, s: boom(s)))
    assert isinstance(make_tracer(Settings(_env_file=None)), NoopTracer)
