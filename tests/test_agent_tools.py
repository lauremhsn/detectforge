"""Agent tools: typed contracts, least privilege, held-out isolation, failure handling."""

import json

import pytest

from detectforge.agent import tools
from detectforge.agent.tools import TOOLS, ToolContext, dispatch, tool_schemas
from detectforge.reference.index import ReferenceIndex, ReferenceRule

TECHNIQUE = "T1053.005"


def reference_rule(rule_id: str, title: str, techniques: list[str]) -> ReferenceRule:
    return ReferenceRule(
        id=rule_id,
        title=title,
        path=f"rules/{rule_id}.yml",
        status="test",
        level="medium",
        description=title,
        techniques=techniques,
        falsepositives=[],
        fields=["Image"],
        unmapped_fields=[],
        evaluable=True,
        can_fire=True,
        detection_text="sel:\n  Image|endswith: x\ncondition: sel\n",
        rule_yaml="title: x",
    )


@pytest.fixture
def index():
    return ReferenceIndex(
        [
            reference_rule("r1", "Scheduled Task Creation", ["T1053.005"]),
            reference_rule("r2", "Certutil Download", ["T1105"]),
        ],
        release="test",
    )


@pytest.fixture
def split(fixture_events):
    events = [e for e in fixture_events if e.technique == TECHNIQUE]
    return [e for e in events if e.split == "tune"], [e for e in events if e.split == "heldout"]


@pytest.fixture
def ctx(split, index, load_rule_text):
    tune, _ = split
    return ToolContext(
        TECHNIQUE, tune, index, original_rule_yaml=load_rule_text("schtasks_create_literal.yml")
    )


def call(ctx, name, **args):
    return dispatch(ctx, name, args)


def test_context_refuses_held_out_events(split, index):
    tune, heldout = split
    with pytest.raises(ValueError, match="tuning-split"):
        ToolContext(TECHNIQUE, tune + heldout, index)


def test_schemas_describe_every_tool():
    schemas = {s["name"]: s for s in tool_schemas()}
    assert set(schemas) == {
        "search_reference_rules",
        "inspect_schema",
        "validate_rule",
        "run_tuning_set",
        "submit",
    }
    assert schemas["submit"]["input_schema"]["required"] == ["rule_yaml", "rationale"]
    assert schemas["search_reference_rules"]["input_schema"]["additionalProperties"] is False


def test_run_tuning_set_reports_misses_and_hides_held_out_transform_types(ctx, load_rule_text):
    result = call(ctx, "run_tuning_set", rule_yaml=load_rule_text("schtasks_create_literal.yml"))
    out = result.output
    assert result.ok and out["valid"]
    assert (out["attacks"], out["detected"], out["false_alarms"]) == (4, 2, 1)
    assert set(out["per_transform"]) == {"none", "insertion", "substitution", "omission"}
    assert [e["event_id"] for e in out["missed_attacks"]] == ["st-002", "st-003"]
    assert [e["event_id"] for e in out["false_alarm_events"]] == ["st-102"]
    assert out["tuning_runs_left"] == ctx.tuning_runs_left


def test_run_tuning_set_compares_with_original(ctx, load_rule_text):
    out = call(ctx, "run_tuning_set", rule_yaml=load_rule_text("schtasks_create_robust.yml")).output
    assert out["original_evasion_resistance"] == pytest.approx(1 / 3)
    assert out["evasion_resistance"] == 1.0 and out["attacks_lost_vs_original"] == []


def test_no_tool_output_leaks_held_out_events(ctx, split, load_rule_text):
    _, heldout = split
    rule = load_rule_text("schtasks_create_robust.yml")
    outputs = [
        call(ctx, "inspect_schema"),
        call(ctx, "validate_rule", rule_yaml=rule),
        call(ctx, "run_tuning_set", rule_yaml=rule),
        call(ctx, "run_tuning_set", rule_yaml="title: ["),
        call(ctx, "search_reference_rules", technique=TECHNIQUE),
        call(ctx, "submit", rule_yaml=rule, rationale="keys on schtasks + create verb"),
    ]
    text = json.dumps([o.model_dump() for o in outputs])
    for e in heldout:
        assert e.event_id not in text and e.command_line not in text
    assert "reordering" not in text and "recoding" not in text  # held-out transform types


def test_tuning_budget_is_enforced(split, index, load_rule_text):
    ctx = ToolContext(TECHNIQUE, split[0], index, max_tuning_runs=1)
    rule = load_rule_text("schtasks_create_robust.yml")
    assert call(ctx, "run_tuning_set", rule_yaml=rule).ok
    result = call(ctx, "run_tuning_set", rule_yaml=rule)
    assert not result.ok and "budget exhausted" in result.error


def test_search_applies_runner_exclusion(split, index):
    ctx = ToolContext(TECHNIQUE, split[0], index, exclude_technique=TECHNIQUE)
    out = call(ctx, "search_reference_rules", query="scheduled task certutil", limit=10).output
    assert [r["id"] for r in out] == ["r2"]
    assert "exclude_technique" not in TOOLS["search_reference_rules"].input_model.model_fields


def test_search_without_index_is_a_clear_error(split):
    result = call(ToolContext(TECHNIQUE, split[0], None), "search_reference_rules", technique=TECHNIQUE)
    assert not result.ok and "unavailable" in result.error


def test_submit_passes_gate_and_is_recorded(ctx, load_rule_text):
    rule = load_rule_text("schtasks_create_robust.yml")
    result = call(ctx, "submit", rule_yaml=rule, rationale="schtasks.exe with a create verb")
    assert result.ok and result.output["passed"]
    assert ctx.accepted is not None and ctx.accepted.rule_yaml == rule


def test_failed_submissions_are_limited(ctx, load_rule_text):
    rule = load_rule_text("schtasks_create_literal.yml")  # fails: lower resistance than required
    for _ in range(tools.MAX_SUBMISSIONS):
        assert call(ctx, "submit", rule_yaml=rule, rationale="x").output["passed"] is False
    result = call(ctx, "submit", rule_yaml=rule, rationale="x")
    assert not result.ok and "no submissions left" in result.error
    assert ctx.accepted is None


@pytest.mark.parametrize(
    ("name", "arguments", "fragment"),
    [
        ("deploy_rule", {}, "unknown tool"),
        ("run_tuning_set", {}, "rule_yaml"),
        ("run_tuning_set", {"rule_yaml": "x", "split": "heldout"}, "split"),
        ("search_reference_rules", {"technique": "1053"}, "technique"),
        ("search_reference_rules", {"query": "x", "limit": 500}, "limit"),
        ("validate_rule", "{not json", "invalid arguments"),
    ],
    ids=[
        "unknown-tool",
        "missing-arg",
        "extra-arg-split",
        "bad-technique",
        "limit-too-high",
        "malformed-json",
    ],
)
def test_malformed_calls_return_errors(ctx, name, arguments, fragment):
    result = dispatch(ctx, name, arguments)
    assert not result.ok and fragment in result.error


def test_json_string_arguments_are_accepted(ctx, load_rule_text):
    payload = json.dumps({"rule_yaml": load_rule_text("schtasks_create_robust.yml")})
    assert dispatch(ctx, "validate_rule", payload).output["valid"]


def test_unexpected_failure_does_not_leak_details(ctx, monkeypatch):
    def boom(ctx, args):
        raise RuntimeError("secret internal detail")

    monkeypatch.setitem(
        TOOLS, "inspect_schema", TOOLS["inspect_schema"].__class__("inspect_schema", "", tools.NoInput, boom)
    )
    result = call(ctx, "inspect_schema")
    assert not result.ok and result.error == "internal error in inspect_schema"


def test_every_call_is_recorded(ctx, load_rule_text):
    call(ctx, "inspect_schema")
    call(ctx, "nope")
    assert [(c.tool, c.ok) for c in ctx.calls] == [("inspect_schema", True), ("nope", False)]
    assert all(c.latency_ms >= 0 for c in ctx.calls)
