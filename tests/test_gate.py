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


def test_zero_benign_events_is_flagged_not_reported_as_clean(tuning, load_rule_text):
    """Regression: with no tuning benign events, an over-broad rule passed with "0 new false alarms"."""
    original = load_rule_text("schtasks_create_literal.yml")
    robust = load_rule_text("schtasks_create_robust.yml")
    with_benign = check(robust, tuning, original_yaml=original)
    assert "false_alarms_tested" in names(with_benign, True)

    attacks_only = [e for e in tuning if e.label == "attack"]
    result = check(robust, attacks_only, original_yaml=original)
    tested = next(c for c in result.checks if c.name == "false_alarms_tested")
    assert not tested.passed and not tested.blocking and "prove nothing" in tested.detail
    assert result.passed  # a warning for the reviewer, never a reason to fail


def test_threshold_is_configurable(tuning, load_rule_text):
    lenient = GateConfig(min_evasion_resistance=0.3, max_false_alarms=1)
    assert check(load_rule_text("schtasks_create_literal.yml"), tuning, config=lenient).passed


def test_hardening_must_not_change_who_wrote_the_rule_or_what_it_cites(tuning, load_rule_text):
    """Regression: a real v7 run 'corrected' a reference link to a URL that doesn't exist."""
    original = load_rule_text("schtasks_create_literal.yml").replace(
        "tags:", "references:\n  - https://learn.microsoft.com/schtasks\ntags:", 1
    )
    robust = load_rule_text("schtasks_create_robust.yml").replace(
        "tags:", "references:\n  - https://learn.microsoft.com/schtasks\ntags:", 1
    )
    assert check(robust, tuning, original_yaml=original).passed

    edited = robust.replace("learn.microsoft.com", "www.microsoft.com").replace(
        "author: DetectForge fixtures", "author: Detection Engineer"
    )
    result = check(edited, tuning, original_yaml=original)
    failed = {c.name: c for c in result.checks if not c.passed}
    assert not result.passed and failed["keeps_original_metadata"].blocking
    assert "author, references" in failed["keeps_original_metadata"].detail
    # Writing a new rule has no original, so there is nothing to keep.
    assert "keeps_original_metadata" not in {c.name for c in check(edited, tuning).checks}
