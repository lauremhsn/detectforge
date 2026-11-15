import json

from detectforge.eval.arms import run_community_arm
from detectforge.eval.metrics import score_rule
from detectforge.reference.index import ReferenceIndex, ReferenceRule
from detectforge.schemas import Event

from conftest import FIXTURES

LITERAL = (FIXTURES / "rules" / "schtasks_create_literal.yml").read_text(encoding="utf-8")
ROBUST = (FIXTURES / "rules" / "schtasks_create_robust.yml").read_text(encoding="utf-8")


def attack(event_id, command, transform, base_id, split="tune"):
    return Event(
        event_id=event_id,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=command,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        original_file_name="schtasks.exe",
        label="attack",
        technique="T1053.005",
        transform=transform,
        base_id=base_id,
        split=split,
    )


BASE = attack("b01", "schtasks.exe /create /tn X /sc onlogon", "none", "b01")
SUB = attack("b01-sub1", "schtasks.exe -create -tn X -sc onlogon", "substitution", "b01")
OMIT = attack("b01-omi1", "schtasks /create /tn X /sc onlogon", "omission", "b01")
EVENTS = [BASE, SUB, OMIT]


def test_literal_rule_is_evaded_by_substitution_not_omission():
    r = score_rule(
        LITERAL,
        EVENTS,
        rule_id="r1",
        title="literal",
        technique="T1053.005",
        selection_split="test",
        source="community",
    )
    assert r.base_detected == 1 and r.base_total == 1
    assert r.evasion_resistance == 0.5
    assert r.resistance_by_transform["substitution"] == 0.0
    assert r.resistance_by_transform["omission"] == 1.0
    assert r.evaded_by == ["substitution"]
    assert r.false_alarm_rate is None  # no benign events supplied


def test_robust_rule_is_fully_resistant():
    r = score_rule(
        ROBUST,
        EVENTS,
        rule_id="r2",
        title="robust",
        technique="T1053.005",
        selection_split="dev",
        source="community",
    )
    assert r.evasion_resistance == 1.0
    assert r.evaded_by == []


def _ref(rule_id, yaml_text):
    return ReferenceRule(
        id=rule_id,
        title=rule_id,
        path=f"rules/{rule_id}.yml",
        status="test",
        level="medium",
        description="",
        techniques=["T1053.005"],
        falsepositives=[],
        fields=["CommandLine"],
        unmapped_fields=[],
        evaluable=True,
        can_fire=True,
        detection_text="",
        rule_yaml=yaml_text,
    )


def test_community_arm_aggregates_micro_average():
    selection = {
        "rules": [
            {
                "id": "r1",
                "title": "literal",
                "technique": "T1053.005",
                "split": "test",
                "base_attacks": ["b01"],
            },
            {
                "id": "r2",
                "title": "robust",
                "technique": "T1053.005",
                "split": "dev",
                "base_attacks": ["b01"],
            },
        ]
    }
    index = ReferenceIndex([_ref("r1", LITERAL), _ref("r2", ROBUST)], "test")
    arm = run_community_arm(selection, index, EVENTS)

    assert arm.rule_count == 2 and arm.valid_rules == 2
    # 4 rule x mutation trials, 3 detected (literal misses the substitution).
    assert arm.overall_evasion_resistance == 0.75
    assert arm.resistance_by_transform["substitution"] == 0.5
    assert arm.resistance_by_transform["omission"] == 1.0
    assert arm.resistance_by_selection_split == {"dev": 1.0, "test": 0.5}
    assert arm.rules_fully_robust == 1 and arm.rules_evaded == 1


def test_arm_result_serializes():
    selection = {
        "rules": [
            {
                "id": "r1",
                "title": "literal",
                "technique": "T1053.005",
                "split": "test",
                "base_attacks": ["b01"],
            },
        ]
    }
    index = ReferenceIndex([_ref("r1", LITERAL)], "test")
    arm = run_community_arm(selection, index, EVENTS)
    assert json.loads(arm.model_dump_json())["arm"] == "community"
