"""Hardening may broaden a rule, never quietly narrow it: dropped fields and dropped exclusions."""

import pytest

from detectforge.gate import GateConfig, check
from detectforge.rules.lint import dropped_fields, dropped_filters
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
