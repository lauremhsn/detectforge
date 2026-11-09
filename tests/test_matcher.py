"""Sigma matching semantics, one rule feature per test."""

import pytest

from detectforge.harness.matcher import can_fire, compile_rule
from detectforge.rules.parse import RuleError, load_rule

from conftest import make_event, make_rule


def fires(detection: str, **event_fields) -> bool:
    return compile_rule(load_rule(make_rule(detection)))(make_event(**event_fields))


SCHTASKS = "C:\\Windows\\System32\\schtasks.exe"


@pytest.mark.parametrize(
    ("detection", "command_line", "expected"),
    [
        # Plain values match the whole field, case-insensitively.
        ("  sel:\n    CommandLine: 'whoami'\n  condition: sel", "WHOAMI", True),
        ("  sel:\n    CommandLine: 'whoami'\n  condition: sel", "whoami /all", False),
        # Wildcards.
        ("  sel:\n    CommandLine: 'who*'\n  condition: sel", "whoami /all", True),
        ("  sel:\n    CommandLine: 'whoam?'\n  condition: sel", "whoami", True),
        ("  sel:\n    CommandLine: 'whoam?'\n  condition: sel", "whoamii", False),
        # Escaped wildcard is literal.
        ("  sel:\n    CommandLine: 'a\\*b'\n  condition: sel", "a*b", True),
        ("  sel:\n    CommandLine: 'a\\*b'\n  condition: sel", "axb", False),
        # Regex metacharacters in plain values are literal.
        ("  sel:\n    CommandLine|contains: '(.+)'\n  condition: sel", "x (.+) y", True),
        ("  sel:\n    CommandLine|contains: '(.+)'\n  condition: sel", "x (ab) y", False),
        # Modifiers.
        ("  sel:\n    CommandLine|startswith: 'net '\n  condition: sel", "net user", True),
        ("  sel:\n    CommandLine|endswith: '/all'\n  condition: sel", "whoami /all", True),
        ("  sel:\n    CommandLine|contains|all: ['a', 'b']\n  condition: sel", "xbxa", True),
        ("  sel:\n    CommandLine|contains|all: ['a', 'b']\n  condition: sel", "xxxa", False),
        ("  sel:\n    CommandLine|contains: ['a', 'b']\n  condition: sel", "xxxb", True),
        ("  sel:\n    CommandLine|windash|contains: ' /create '\n  condition: sel", "x -create y", True),
        ("  sel:\n    CommandLine|cased: 'Whoami'\n  condition: sel", "whoami", False),
        ("  sel:\n    CommandLine|cased: 'Whoami'\n  condition: sel", "Whoami", True),
        ("  sel:\n    CommandLine|re: 'who.mi'\n  condition: sel", "x whoami y", True),
        ("  sel:\n    CommandLine|re: 'WHOAMI'\n  condition: sel", "whoami", False),
        ("  sel:\n    CommandLine|re|i: 'WHOAMI'\n  condition: sel", "whoami", True),
        (
            "  sel:\n    CommandLine|base64offset|contains: 'http'\n  condition: sel",
            "-e aHR0cDovL2V2aWw=",
            True,
        ),
        # Keywords match anywhere in any field.
        ("  keywords:\n    - 'mimikatz'\n  condition: keywords", "run MimiKatz now", True),
        ("  keywords:\n    - 'mimikatz'\n  condition: keywords", "run notepad", False),
    ],
)
def test_value_semantics(detection, command_line, expected):
    assert fires(detection, command_line=command_line) is expected


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("img and cli", True),
        ("img and not cli", False),
        ("img and (cli or other)", True),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("all of them", False),
        ("1 of them and not other", True),
    ],
)
def test_condition_logic(condition, expected):
    detection = (
        f"  img:\n    Image|endswith: '\\schtasks.exe'\n"
        f"  cli:\n    CommandLine|contains: 'create'\n"
        f"  sel_a:\n    CommandLine|contains: 'create'\n"
        f"  sel_b:\n    CommandLine|contains: 'delete'\n"
        f"  other:\n    ParentImage|endswith: '\\winword.exe'\n"
        f"  condition: {condition}"
    )
    assert fires(detection, image=SCHTASKS, command_line="schtasks /create") is expected


def test_list_of_maps_is_or_and_map_is_and():
    detection = (
        "  sel:\n"
        "    - Image|endswith: '\\cmd.exe'\n"
        "      CommandLine|contains: 'nope'\n"
        "    - CommandLine|contains: 'whoami'\n"
        "  condition: sel"
    )
    assert fires(detection, command_line="whoami")
    assert not fires(detection, command_line="dir")


def test_field_outside_schema_is_absent():
    assert not fires("  sel:\n    User: 'SYSTEM'\n  condition: sel")
    assert fires("  sel:\n    User: null\n  condition: sel")
    assert fires("  sel:\n    User|exists: false\n  condition: sel")
    assert fires("  sel:\n    Image|exists: true\n  condition: sel")


def test_optional_sysmon_fields_match_when_captured():
    detection = "  sel:\n    OriginalFileName: 'schtasks.exe'\n  condition: sel"
    assert fires(detection, original_file_name="schtasks.exe")
    assert not fires(detection)  # not captured -> absent
    assert fires(
        "  sel:\n    ParentCommandLine|contains: 'winword'\n  condition: sel",
        parent_command_line='"C:\\Program Files\\Office\\WINWORD.EXE" /n',
    )


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        # Missing field only as an alternative (OR): still fires through Image.
        ("  sel:\n    - Image|endswith: '\\x.exe'\n    - User: 'SYSTEM'\n  condition: sel", True),
        # Missing field required (AND, or alone): can never fire.
        ("  sel:\n    Image|endswith: '\\x.exe'\n    User: 'SYSTEM'\n  condition: sel", False),
        ("  sel:\n    User: 'SYSTEM'\n  condition: sel", False),
        # In a filter: "not <always false>" is always true, so the rule still fires.
        ("  sel:\n    Image: x\n  filter:\n    User: 'SYSTEM'\n  condition: sel and not filter", True),
        # Checking that the absent field is null is always true.
        ("  sel:\n    User: null\n  condition: sel", True),
        ("  sel:\n    Image: x\n  condition: sel", True),
    ],
    ids=["or-branch", "and-required", "alone", "in-filter", "null-check", "no-missing-field"],
)
def test_can_fire(detection, expected):
    assert can_fire(load_rule(make_rule(detection))) is expected


def test_invalid_regex_is_rule_error():
    with pytest.raises(RuleError, match=r"(?i)regular expression"):
        compile_rule(load_rule(make_rule("  sel:\n    CommandLine|re: '(unclosed'\n  condition: sel")))


def test_unsupported_modifier_is_rule_error():
    with pytest.raises(RuleError, match="unsupported"):
        compile_rule(load_rule(make_rule("  sel:\n    CommandLine|fieldref: Image\n  condition: sel")))
