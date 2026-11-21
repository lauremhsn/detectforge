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


def test_an_attack_the_rule_already_misses_does_not_make_an_exclusion_a_bypass():
    """Regression: an unsatisfiable exclusion was blocked because the rule already missed one attack."""
    missed = _attack("a3", "schtasks /change /tn evil")  # no 'create': the rule misses it un-injected
    candidate = _with_filter(
        "filter_x: {CommandLine|re: '^backup-job-[0-9]+$'}", "selection and not filter_x"
    )
    checks = _exclusion_bypass(ORIGINAL, candidate, [*ATTACKS, missed])
    assert _named(checks, "no_bypassable_exclusions").passed


def test_a_written_rule_is_checked_too_every_exclusion_counts_as_added():
    candidate = _with_filter("filter_x: {CommandLine|contains: 'Backup'}", "selection and not filter_x")
    blk = _named(_exclusion_bypass(None, candidate, ATTACKS), "no_bypassable_exclusions")
    assert not blk.passed and "backup" in blk.detail


def test_the_gate_runs_the_exclusion_check_on_written_rules():
    from detectforge.gate import check

    candidate = _with_filter("filter_x: {CommandLine|contains: 'Backup'}", "selection and not filter_x")
    result = check(candidate, ATTACKS)  # no original: a written rule
    assert not result.passed
    assert any(c.name == "no_bypassable_exclusions" and not c.passed for c in result.checks)


def test_an_exclusion_with_spaces_is_probed_with_its_spaces():
    """Regression: a written rule excluded ' query ' (spaces included); the probe stripped the trailing
    space, no longer matched, and the gate called it safe, though appending ' query x' evades the rule."""
    candidate = _with_filter("filter_x: {CommandLine|contains: ' query '}", "selection and not filter_x")
    blk = _named(_exclusion_bypass(None, candidate, ATTACKS), "no_bypassable_exclusions")
    assert not blk.passed and "query" in blk.detail
