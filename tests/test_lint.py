"""Hardening may broaden a rule, never quietly narrow it: dropped fields and dropped exclusions."""

import pytest

from detectforge.gate import GateConfig, check
from detectforge.rules.lint import (
    copied_literals,
    dropped_fields,
    dropped_filters,
    short_bare_values,
    unusual_characters,
)
from detectforge.rules.parse import load_rule

from conftest import make_rule

ORIGINAL = make_rule(
    "  selection:\n"
    "    - Image|endswith: '\\schtasks.exe'\n"
    "    - Hashes|contains: 'IMPHASH=ABC'\n"
    "  selection_cli:\n"
    "    CommandLine|contains: ' /create '\n"
    "  filter_vendor:\n"
    "    CommandLine|contains: 'ExampleVendorUpdate'\n"
    "  filter_empty:\n"
    "    ParentImage: null\n"
    "  condition: all of selection* and not 1 of filter_*"
)


def lint(original: str, candidate: str):
    a, b = load_rule(original), load_rule(candidate)
    return dropped_fields(a, b), dropped_filters(a, b)


def test_identical_rule_drops_nothing():
    # Regression: SigmaNull has no stable str(), so `null` filters used to look "dropped".
    assert lint(ORIGINAL, ORIGINAL) == ([], [])


def test_broadening_the_command_line_check_is_fine():
    broadened = ORIGINAL.replace("CommandLine|contains: ' /create '", "CommandLine|re: '[/-]create'")
    assert lint(ORIGINAL, broadened) == ([], [])


def test_dropping_an_untestable_branch_is_flagged():
    narrowed = ORIGINAL.replace("    - Hashes|contains: 'IMPHASH=ABC'\n", "")
    fields, filters = lint(ORIGINAL, narrowed)
    assert fields == ["Hashes"] and filters == []


def test_dropping_an_exclusion_is_flagged():
    no_filter = ORIGINAL.replace("  filter_vendor:\n    CommandLine|contains: 'ExampleVendorUpdate'\n", "")
    fields, filters = lint(ORIGINAL, no_filter)
    assert fields == []
    assert filters == ["CommandLine: *examplevendorupdate*"]


def test_exclusion_match_ignores_case_and_detection_names():
    renamed = ORIGINAL.replace("filter_vendor", "filter_known_updater").replace(
        "ExampleVendorUpdate", "examplevendorupdate"
    )
    assert lint(ORIGINAL, renamed) == ([], [])


@pytest.fixture
def tuning(fixture_events):
    return [e for e in fixture_events if e.technique == "T1053.005" and e.split == "tune"]


def names(result, passed):
    return {c.name for c in result.checks if c.passed is passed}


def test_gate_rejects_rules_elastic_cannot_run(tuning, load_rule_text):
    cased = load_rule_text("schtasks_create_robust.yml").replace(
        "CommandLine|contains:", "CommandLine|cased:"
    )
    result = check(cased, tuning)
    assert "deployable" in names(result, False)
    assert "Case-sensitive" in next(c.detail for c in result.checks if c.name == "deployable")


def test_gate_deploy_targets_are_configurable(tuning, load_rule_text):
    cased = load_rule_text("schtasks_create_robust.yml").replace(
        "CommandLine|contains:", "CommandLine|cased:"
    )
    result = check(cased, tuning, config=GateConfig(deploy_targets=["eql"]))
    assert "deployable" in names(result, True)


def test_gate_flags_narrowing_when_hardening(tuning, load_rule_text):
    original = load_rule_text("schtasks_create_literal.yml")
    without_original_file_name = load_rule_text("schtasks_create_robust.yml").replace(
        "    - OriginalFileName: 'schtasks.exe'\n", ""
    )
    result = check(without_original_file_name, tuning, original_yaml=original)
    assert not result.passed and "keeps_original_fields" in names(result, False)
    assert "OriginalFileName" in next(c.detail for c in result.checks if c.name == "keeps_original_fields")


def test_gate_scope_checks_only_apply_to_hardening(tuning, load_rule_text):
    result = check(load_rule_text("schtasks_create_robust.yml"), tuning)
    assert not {"keeps_original_fields", "keeps_original_filters"} & {c.name for c in result.checks}


# ---- overfitting ----------------------------------------------------------------------------

OVERFITTED = make_rule(
    "  selection:\n"
    "    Image|endswith: '\\reg.exe'\n"
    "    CommandLine|re: '(?i)\\s+a[\\xad\\u200b]*d[\\xad\\u200b]*d\\s+'\n"
    "  condition: selection"
)


def test_unusual_characters_found_in_escapes_and_literals():
    found = unusual_characters(OVERFITTED)
    assert found == ["U+00AD SOFT HYPHEN", "U+200B ZERO WIDTH SPACE"]
    literal = make_rule("  sel:\n    CommandLine|contains: 'ᵃᵈᵈ'\n  condition: sel")
    assert unusual_characters(literal) == ["U+1D43 MODIFIER LETTER SMALL A", "U+1D48 MODIFIER LETTER SMALL D"]


def test_characters_the_original_already_had_are_fine():
    assert unusual_characters(OVERFITTED, original_yaml=OVERFITTED) == []


def test_plain_ascii_and_windash_are_not_unusual():
    plain = make_rule(
        "  sel:\n    CommandLine|windash|contains: ' /create '\n    CommandLine|re: '\\x2f'\n  condition: sel"
    )
    assert unusual_characters(plain) == []


def test_copied_literals_only_flags_new_long_command_line_values():
    attacks = ['schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"']
    candidate = make_rule(
        "  sel:\n"
        "    Image|endswith: '\\schtasks.exe'\n"
        "    OriginalFileName: 'schtasks.exe'\n"
        "    CommandLine|contains:\n"
        "      - 'T1053_005_OnLogon'\n"
        "      - '/create'\n"
        "    CommandLine|re: 'T1053_005_OnLogon'\n"
        "  condition: sel"
    )
    assert copied_literals(candidate, attacks) == ["T1053_005_OnLogon"]
    assert copied_literals(candidate, attacks, original_yaml=candidate) == []  # already in the original


def test_gate_rejects_memorised_characters_but_only_warns_on_copied_strings(tuning, load_rule_text):
    robust = load_rule_text("schtasks_create_robust.yml")
    memorised = robust.replace("CommandLine|contains: 'create'", "CommandLine|re: 'c\u200breate|create'")
    rejected = check(memorised, tuning)
    assert not rejected.passed and "no_unusual_characters" in names(rejected, False)

    copied = robust.replace(  # an extra alternative copied from st-001's command line
        "CommandLine|contains: 'create'",
        "CommandLine|contains:\n      - 'create'\n      - 'C:\\Users\\Public\\update.exe'",
    )
    result = check(copied, tuning, config=GateConfig(max_false_alarms=1))
    warning = next(c for c in result.checks if c.name == "no_copied_test_strings")
    assert not warning.passed and not warning.blocking
    assert result.passed  # a warning never fails the gate


def test_gate_warns_when_hardening_adds_a_required_field(tuning, load_rule_text):
    original = load_rule_text("schtasks_create_literal.yml")
    both_required = load_rule_text("schtasks_create_robust.yml").replace(
        "    - Image|endswith: '\\schtasks.exe'\n    - OriginalFileName: 'schtasks.exe'\n",
        "    Image|endswith: '\\schtasks.exe'\n    OriginalFileName: 'schtasks.exe'\n",
    )
    result = check(both_required, tuning, original_yaml=original)
    warning = next(c for c in result.checks if c.name == "no_new_required_fields")
    assert not warning.passed and not warning.blocking and "OriginalFileName" in warning.detail
    assert result.passed  # a warning, not a rejection


def test_gate_reports_a_rule_too_slow_to_evaluate(monkeypatch):
    from detectforge.harness import matcher

    from conftest import make_event

    monkeypatch.setattr(matcher, "REGEX_TIMEOUT_S", 0.05)
    slow = make_rule("  sel:\n    CommandLine|re: '(a|aa)+$'\n  condition: sel")
    events = [make_event(command_line="a" * 40 + "!")]  # classic catastrophic-backtracking input
    result = check(slow, events)
    assert not result.passed and result.checks[-1].name == "evaluable"
    assert "catastrophic backtracking" in result.checks[-1].detail


def test_short_bare_values_flags_new_letters_without_a_delimiter():
    original = make_rule("  sel:\n    CommandLine|contains: '/ru '\n  condition: sel")
    candidate = make_rule(
        "  sel:\n"
        "    Image|endswith: '\\sc.exe'\n"  # program names are fine
        "    CommandLine|contains:\n"
        "      - 'ru'\n"  # matches "run", "true", "group"
        "      - '/ru '\n"  # kept from the original
        "      - ' -ru '\n"  # has a delimiter
        "      - 'create'\n"  # long enough
        "    CommandLine|re: 'ru'\n"  # regexes are out of scope
        "  condition: sel"
    )
    assert short_bare_values(candidate, original) == ["ru"]
    assert short_bare_values(original, original) == []


def test_gate_rejects_short_bare_values(tuning, load_rule_text):
    robust = load_rule_text("schtasks_create_robust.yml")
    broad = robust.replace("CommandLine|contains: 'create'", "CommandLine|contains: 'cr'")
    result = check(broad, tuning, config=GateConfig(max_false_alarms=99))
    assert not result.passed and "no_short_bare_values" in names(result, False)
    assert check(robust, tuning, config=GateConfig(max_false_alarms=99)).passed
