"""The offline agent-metrics script: how it reads a transcript, and that its leak check is exact."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import agent_metrics as am


def _transcript(rule: str = "title: x") -> list[dict]:
    def call(i: int, name: str, args: dict) -> dict:
        return {"id": f"c{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}

    return [
        {"role": "system", "content": "prompt"},
        {"role": "assistant", "tool_calls": [call(1, "run_tuning_set", {"rule_yaml": rule})]},
        {
            "role": "tool",
            "tool_call_id": "c1",
            "content": json.dumps(
                {
                    "ok": True,
                    "output": {"missed_attacks": [{"command_line": "wmic process call create notepad.exe"}]},
                }
            ),
        },
        {"role": "assistant", "tool_calls": [call(2, "run_tuning_set", {"rule_yaml": rule})]},
        {"role": "tool", "tool_call_id": "c2", "content": json.dumps({"ok": True, "output": {}})},
        {"role": "assistant", "tool_calls": [call(3, "submit", {"rule_yaml": rule})]},
        {
            "role": "tool",
            "tool_call_id": "c3",
            "content": json.dumps({"ok": True, "output": {"passed": True}}),
        },
    ]


def test_trajectory_pairs_each_call_with_its_result():
    steps = am.trajectory(_transcript())
    assert [name for name, _, _ in steps] == ["run_tuning_set", "run_tuning_set", "submit"]
    assert steps[-1][2]["output"]["passed"] is True


def test_strings_reads_json_inside_tool_results():
    assert "wmic process call create notepad.exe" in am.strings(_transcript())


def test_leak_check_is_exact_not_substring():
    # A held-out omission variant is a substring of the tuning command it came from: not a leak.
    seen = set(am.strings(_transcript()))
    assert not ({"wmic process call create notepad"} & seen)
    assert {"wmic process call create notepad.exe"} & seen
