"""The agent arms (adapted, written) and the three-arm comparison.

The one risky bit is the setup_key match: run_agent_arm must find each rule's saved run on disk without
a model client. One test writes a real run and proves the match end to end; the rest use a small fake
done-map for the scoring, cost and missing-run behaviour.
"""

import json

from detectforge.agent.loop import AgentRun
from detectforge.agent.runner import HardeningOutcome, run_provenance, scope_events
from detectforge.eval import arms
from detectforge.gate import GateResult
from detectforge.llm import ModelCallRecord
from detectforge.reference.index import ReferenceIndex, ReferenceRule
from detectforge.schemas import Event, RuleRecord

from conftest import FIXTURES

LITERAL = (FIXTURES / "rules" / "schtasks_create_literal.yml").read_text(encoding="utf-8")
ROBUST = (FIXTURES / "rules" / "schtasks_create_robust.yml").read_text(encoding="utf-8")
TECH = "T1053.005"


def attack(event_id, command, transform, base_id, split="tune"):
    return Event(
        event_id=event_id,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=command,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        original_file_name="schtasks.exe",
        label="attack",
        technique=TECH,
        transform=transform,
        base_id=base_id,
        split=split,
    )


BASE = attack("b01", "schtasks.exe /create /tn X /sc onlogon", "none", "b01")
SUB = attack("b01-sub1", "schtasks.exe -create -tn X -sc onlogon", "substitution", "b01")
OMIT = attack("b01-omi1", "schtasks /create /tn X /sc onlogon", "omission", "b01", split="heldout")
EVENTS = [BASE, SUB, OMIT]
SELECTION = {
    "rules": [{"id": "r1", "title": "sched", "technique": TECH, "split": "dev", "base_attacks": ["b01"]}]
}


def _ref(rule_id, yaml_text):
    return ReferenceRule(
        id=rule_id,
        title=rule_id,
        path=f"rules/{rule_id}.yml",
        status="test",
        level="medium",
        description="",
        techniques=[TECH],
        falsepositives=[],
        fields=["CommandLine"],
        unmapped_fields=[],
        evaluable=True,
        can_fire=True,
        detection_text="",
        rule_yaml=yaml_text,
    )


def _run(final_yaml, *, calls=3, status="passed"):
    return AgentRun(
        trace_id="t01",
        technique=TECH,
        model="m",
        status=status,
        original_rule_yaml="",
        final_rule_yaml=final_yaml,
        final_source="accepted",
        gate=GateResult(passed=True, checks=[]),
        tuning_evasion_resistance_before=0.5,
        tuning_evasion_resistance_after=1.0,
        tuning_false_alarms_before=0,
        tuning_false_alarms_after=0,
        tuning_runs_used=1,
        model_calls=[ModelCallRecord(model="m", ok=True, latency_ms=1.0) for _ in range(calls)],
        tool_calls=[],
        prompt_tokens=100,
        completion_tokens=50,
        duration_s=2.0,
        record=RuleRecord(rule_yaml=final_yaml, source="adapted", technique=TECH, trace_id="t01", version=1),
    )


def test_run_agent_arm_finds_the_saved_run_by_setup_key(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")  # community rule is the literal (gets evaded)
    start = LITERAL  # harden starts from the community rule
    prov = run_provenance(start, scope_events(EVENTS, TECH, {"b01"}), None, "m")
    outcome = HardeningOutcome(run=_run(ROBUST), heldout_evaluation=None, provenance=prov)
    (tmp_path / "run.json").write_text(outcome.model_dump_json(), encoding="utf-8")

    arm = arms.run_agent_arm(SELECTION, index, EVENTS, tmp_path, "m", mode="harden")
    assert arm.arm == "adapted"
    assert arm.overall_evasion_resistance == 1.0  # the agent's robust rule caught both mutations
    assert arm.valid_rules == 1
    assert arm.cost.model_calls == 3 and arm.cost.accepted_rules == 1
    assert arm.cost.calls_per_accepted_rule == 3.0


def test_missing_harden_run_falls_back_to_the_community_rule(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    community = arms.run_community_arm(SELECTION, index, EVENTS)
    arm = arms.run_agent_arm(SELECTION, index, EVENTS, tmp_path, "m", mode="harden")
    assert arm.valid_rules == 1  # untouched rule is the community rule, not a gap
    assert arm.overall_evasion_resistance == community.overall_evasion_resistance
    assert arm.rules[0].error is None
    assert arm.incomplete_rules == []  # 0 runs = untouched, not incomplete
    assert arm.cost.model_calls == 0 and arm.cost.calls_per_accepted_rule is None


def test_missing_written_run_is_a_coverage_gap(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    arm = arms.run_agent_arm(SELECTION, index, EVENTS, tmp_path, "m", mode="write")
    assert arm.valid_rules == 0  # no written rule -> a real gap
    assert arm.overall_evasion_resistance == 0.0
    assert arm.rules[0].error == "no saved agent run"


def test_mean_and_spread_over_three_runs(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    prov = run_provenance(LITERAL, scope_events(EVENTS, TECH, {"b01"}), None, "m")
    for i, y in enumerate((ROBUST, ROBUST, LITERAL)):  # two catch all, one is the evaded literal
        outcome = HardeningOutcome(run=_run(y), heldout_evaluation=None, provenance=prov)
        (tmp_path / f"run{i}.json").write_text(outcome.model_dump_json(), encoding="utf-8")
    arm = arms.run_agent_arm(SELECTION, index, EVENTS, tmp_path, "m", mode="harden")
    assert arm.runs_per_rule == 3
    assert arm.incomplete_rules == []  # exactly 3 runs
    lo, hi = arm.spread
    assert lo < hi  # the literal run drags one slot below the robust ones
    assert lo <= arm.overall_evasion_resistance <= hi


def test_fewer_than_three_runs_is_flagged(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    prov = run_provenance(LITERAL, scope_events(EVENTS, TECH, {"b01"}), None, "m")
    for i in range(2):  # only 2 of the wanted 3
        outcome = HardeningOutcome(run=_run(ROBUST), heldout_evaluation=None, provenance=prov)
        (tmp_path / f"run{i}.json").write_text(outcome.model_dump_json(), encoding="utf-8")
    arm = arms.run_agent_arm(SELECTION, index, EVENTS, tmp_path, "m", mode="harden")
    assert arm.incomplete_rules == ["r1"]


def test_written_mode_starts_from_no_rule(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    prov = run_provenance(None, scope_events(EVENTS, TECH, {"b01"}), None, "m")  # writing: start is None
    outcome = HardeningOutcome(run=_run(ROBUST), heldout_evaluation=None, provenance=prov)
    (tmp_path / "run.json").write_text(outcome.model_dump_json(), encoding="utf-8")

    arm = arms.run_agent_arm(SELECTION, index, EVENTS, tmp_path, "m", mode="write")
    assert arm.arm == "written" and arm.overall_evasion_resistance == 1.0


def _benign(event_id, split):
    return Event(
        event_id=event_id,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks /create /tn Backup /sc daily",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        original_file_name="schtasks.exe",
        label="benign",
        technique=TECH,
        transform="none",
        base_id=event_id,
        split=split,
    )


def test_false_alarm_rate_counts_only_held_out_benign():
    index = ReferenceIndex([_ref("r1", ROBUST)], "test")  # robust fires on any schtasks /create
    events = [*EVENTS, _benign("nb-h", "heldout"), _benign("nb-t", "tune")]
    arm = arms.run_community_arm(SELECTION, index, events)
    assert arm.false_alarm_rate == 1.0  # the one held-out benign fired; the tune one isn't counted


def test_three_arm_comparison_names_all_three(tmp_path):
    index = ReferenceIndex([_ref("r1", ROBUST)], "test")
    c = arms.three_arm_comparison(SELECTION, index, EVENTS, tmp_path, "m")
    assert [c.community.arm, c.adapted.arm, c.written.arm] == ["community", "adapted", "written"]
    assert json.loads(c.model_dump_json())["community"]["arm"] == "community"
    assert c.adapted_effect is None  # no rule was touched


def test_adapted_effect_is_only_the_touched_rules(tmp_path):
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    prov = run_provenance(LITERAL, scope_events(EVENTS, TECH, {"b01"}), None, "m")
    outcome = HardeningOutcome(run=_run(ROBUST), heldout_evaluation=None, provenance=prov)
    (tmp_path / "run.json").write_text(outcome.model_dump_json(), encoding="utf-8")
    c = arms.three_arm_comparison(SELECTION, index, EVENTS, tmp_path, "m")
    assert c.adapted_effect.touched_rules == 1
    assert c.adapted_effect.adapted_resistance == 1.0  # the robust rule the agent produced
    assert c.adapted_effect.community_resistance == c.community.overall_evasion_resistance
