import pytest

from detectforge.gate import GateConfig, check


@pytest.fixture
def tuning(fixture_events):
    return [e for e in fixture_events if e.technique == "T1053.005" and e.split == "tune"]


def names(result, passed):
    return {c.name for c in result.checks if c.passed is passed}


def test_literal_rule_fails_with_all_reasons(tuning, load_rule_text):
    result = check(load_rule_text("schtasks_create_literal.yml"), tuning)
    assert not result.passed
    assert names(result, False) == {"evasion_resistance", "false_alarms"}  # 1/3 mutations; vendor FP
    assert "detects_unmutated_attacks" in names(result, True)


def test_hardened_rule_passes_against_its_original(tuning, load_rule_text):
    result = check(
        load_rule_text("schtasks_create_robust.yml"),
        tuning,
        original_yaml=load_rule_text("schtasks_create_literal.yml"),
    )
    assert result.passed, result.checks
    # The vendor false alarm existed before hardening, so it is not a *new* one.
    assert {"no_lost_attacks", "no_new_false_alarms"} <= names(result, True)


def test_regression_against_original_fails(tuning, load_rule_text):
    result = check(
        load_rule_text("schtasks_create_literal.yml"),
        tuning,
        original_yaml=load_rule_text("schtasks_create_robust.yml"),
    )
    assert not result.passed and "no_lost_attacks" in names(result, False)


def test_invalid_rule_stops_at_validation(tuning):
    result = check("title: [", tuning)
    assert not result.passed and [c.name for c in result.checks] == ["valid"]


def test_threshold_is_configurable(tuning, load_rule_text):
    lenient = GateConfig(min_evasion_resistance=0.3, max_false_alarms=1)
    assert check(load_rule_text("schtasks_create_literal.yml"), tuning, config=lenient).passed
