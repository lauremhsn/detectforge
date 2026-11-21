from detectforge.gate import _anchor, _exclusion_bypass
from detectforge.schemas import Event

BASE = """\
title: Schtasks Create (test)
id: 11111111-1111-1111-1111-111111111111
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\schtasks.exe'
    CommandLine|contains: 'create'
"""
ORIGINAL = BASE + "  condition: selection\n"


def _with_filter(filt: str, cond: str) -> str:
    return BASE + f"  {filt}\n  condition: {cond}\n"


def _attack(eid, cmd, parent="C:\\Windows\\System32\\cmd.exe"):
    return Event(
        event_id=eid,
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line=cmd,
        parent_image=parent,
        label="attack",
        technique="T1053.005",
        transform="none",
        base_id=eid,
        split="heldout",
    )


ATTACKS = [
    _attack("a1", "schtasks /create /ru system /tn evil"),
    _attack("a2", "schtasks /create /sc onlogon /tn evil2"),
]


def _named(checks, name):
    return next(c for c in checks if c.name == name)


def test_free_command_line_exclusion_is_blocked():
    candidate = _with_filter("filter_x: {CommandLine|contains: 'Backup'}", "selection and not filter_x")
    checks = _exclusion_bypass(ORIGINAL, candidate, ATTACKS)
    blk = _named(checks, "no_bypassable_exclusions")
    assert not blk.passed and "backup" in blk.detail  # attacker adds "backup", rule misses it


def test_privileged_path_exclusion_is_a_warning_not_a_block():
    candidate = _with_filter(
        "filter_x: {ParentImage: 'C:\\Program Files\\Co\\installer.exe'}", "selection and not filter_x"
    )
    checks = _exclusion_bypass(ORIGINAL, candidate, ATTACKS)
    assert _named(checks, "no_bypassable_exclusions").passed  # not blocked
    judge = _named(checks, "exclusion_bypass_judgment")
    assert not judge.passed and not judge.blocking  # warns the reviewer, doesn't fail the gate


def test_original_exclusion_only_warns_even_if_bypassable():
    orig = _with_filter("filter_o: {CommandLine|contains: 'Backup'}", "selection and not filter_o")
    checks = _exclusion_bypass(orig, orig, ATTACKS)  # candidate == original: nothing added
    assert _named(checks, "no_bypassable_exclusions").passed
    assert "(original)" in _named(checks, "exclusion_bypass_judgment").detail


def test_anchor_grading():
    assert _anchor("CommandLine", "anything") == "free"
    assert _anchor("ParentImage", "\\notepad.exe") == "free"  # bare filename
    assert _anchor("ParentImage", "C:\\Program Files\\Co\\x.exe") == "privileged"
