import pytest
import yaml

from detectforge.dataset import atomic
from detectforge.dataset.selection import PickedRule, SelectionConfig, SelectionError, build_selection
from detectforge.reference.index import ReferenceIndex, ReferenceRule

from conftest import FIXTURES

COMMIT = "0" * 40

ART_DOC = {
    "attack_technique": "T1053.005",
    "atomic_tests": [
        {
            "name": "Scheduled task",
            "supported_platforms": ["windows"],
            "input_arguments": {"task": {"default": "Updater"}},
            "executor": {
                "name": "command_prompt",
                "command": (
                    'REM setup\nschtasks /create /tn "#{task}" /tr "%temp%\\a.exe" /sc onlogon\necho done'
                ),
            },
        },
        {
            "name": "Linux only",
            "supported_platforms": ["linux"],
            "executor": {"name": "sh", "command": "crontab -l"},
        },
        {
            "name": "PowerShell cmdlet",
            "supported_platforms": ["windows"],
            "executor": {"name": "powershell", "command": "Register-ScheduledTask -TaskName x"},
        },
    ],
}


def reference_rule(rule_id: str, fixture: str, techniques: list[str]) -> ReferenceRule:
    return ReferenceRule(
        id=rule_id,
        title=fixture,
        path=f"rules/{fixture}",
        status="test",
        level="medium",
        description="",
        techniques=techniques,
        falsepositives=[],
        fields=["CommandLine"],
        unmapped_fields=[],
        evaluable=True,
        can_fire=True,
        detection_text="",
        rule_yaml=(FIXTURES / "rules" / fixture).read_text(encoding="utf-8"),
    )


@pytest.fixture
def art_cache(tmp_path):
    (tmp_path / COMMIT).mkdir()
    (tmp_path / COMMIT / "T1053.005.yaml").write_text(yaml.safe_dump(ART_DOC), encoding="utf-8")
    (tmp_path / COMMIT / "T1105.yaml").write_text(
        yaml.safe_dump({"attack_technique": "T1105", "atomic_tests": []}), encoding="utf-8"
    )
    return tmp_path


def test_expand_fills_shell_variables():
    assert atomic.expand("x %TEMP%\\a $env:TEMP") == (
        "x C:\\Users\\analyst\\AppData\\Local\\Temp\\a C:\\Users\\analyst\\AppData\\Local\\Temp"
    )
    assert atomic.expand("PathToAtomicsFolder\\T1\\x") == "C:\\AtomicRedTeam\\atomics\\T1\\x"


def test_windows_commands_keeps_only_process_lines():
    cmds = atomic.windows_commands(ART_DOC)
    assert len(cmds) == 1
    cmd = cmds[0]
    assert cmd.image == "C:\\Windows\\System32\\schtasks.exe"
    assert cmd.parent_image == atomic.CMD
    assert '/tn "Updater"' in cmd.command_line
    assert "C:\\Users\\analyst\\AppData\\Local\\Temp\\a.exe" in cmd.command_line


def test_load_tests_reads_cache_without_network(art_cache):
    assert atomic.load_tests("T1053.005", art_cache, COMMIT)["attack_technique"] == "T1053.005"


def test_build_selection(art_cache):
    index = ReferenceIndex([reference_rule("r1", "schtasks_create_robust.yml", ["T1053.005"])], "test")
    config = SelectionConfig(
        atomic_red_team_commit=COMMIT,
        dev_techniques=["T1053.005"],
        rules=[PickedRule(id="r1", technique="T1053.005")],
    )
    result = build_selection(config, index, art_cache)
    assert result.rules[0].split == "dev"
    assert result.rules[0].base_attacks == ["T1053.005-b01"]
    event = result.base_attacks[0].to_event()
    assert event.base_id == event.event_id and event.transform == "none"


def test_rule_that_fires_on_nothing_is_rejected(art_cache):
    index = ReferenceIndex([reference_rule("r2", "certutil_download_literal.yml", ["T1105"])], "test")
    config = SelectionConfig(
        atomic_red_team_commit=COMMIT, dev_techniques=[], rules=[PickedRule(id="r2", technique="T1105")]
    )
    with pytest.raises(SelectionError, match="fires on no base attack"):
        build_selection(config, index, art_cache)


def test_dev_test_family_overlap_is_rejected(art_cache):
    index = ReferenceIndex(
        [
            reference_rule("a", "schtasks_create_robust.yml", ["T1053.005"]),
            reference_rule("b", "schtasks_create_literal.yml", ["T1053.005"]),
        ],
        "test",
    )
    config = SelectionConfig(
        atomic_red_team_commit=COMMIT,
        dev_techniques=["T1053.005"],
        rules=[PickedRule(id="a", technique="T1053.005"), PickedRule(id="b", technique="T1053.002")],
    )
    with pytest.raises(SelectionError, match="share technique families"):
        build_selection(config, index, art_cache)


def test_unknown_rule_id_is_rejected(art_cache):
    config = SelectionConfig(dev_techniques=[], rules=[PickedRule(id="nope", technique="T1105")])
    with pytest.raises(SelectionError, match="not in SigmaHQ"):
        build_selection(config, ReferenceIndex([], "test"), art_cache)
