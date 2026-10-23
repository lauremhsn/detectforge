import pytest

from detectforge.harness import run
from detectforge.rules.parse import MAX_RULE_BYTES

from conftest import make_event, make_rule


def by_technique(events, technique):
    return [e for e in events if e.technique == technique]


def test_literal_schtasks_rule_scorecard(fixture_events, load_rule_text):
    card = run(load_rule_text("schtasks_create_literal.yml"), by_technique(fixture_events, "T1053.005"))

    assert card.valid and card.error is None
    assert (card.hits, card.misses, card.false_alarms) == (2, 3, 1)
    assert card.matched_event_ids == ["st-001", "st-004", "st-102"]
    pt = card.per_transform
    assert (pt["none"].hits, pt["none"].benign, pt["none"].false_alarms) == (1, 3, 1)
    assert pt["insertion"].misses == 1  # /"create"
    assert pt["substitution"].misses == 1  # -create
    assert pt["omission"].hits == 1  # schtasks without .exe
    assert pt["reordering"].misses == 1  # /create at end, no trailing space
    assert pt["recoding"].attacks == 0


def test_behavior_based_rule_catches_all_schtasks_variants(fixture_events, load_rule_text):
    card = run(load_rule_text("schtasks_create_robust.yml"), by_technique(fixture_events, "T1053.005"))
    assert (card.hits, card.misses, card.false_alarms) == (5, 0, 1)


def test_literal_certutil_rule_scorecard(fixture_events, load_rule_text):
    card = run(load_rule_text("certutil_download_literal.yml"), by_technique(fixture_events, "T1105"))
    assert (card.hits, card.misses, card.false_alarms) == (4, 2, 0)
    assert card.matched_event_ids == ["cu-001", "cu-004", "cu-005", "cu-006"]
    assert card.per_transform["insertion"].misses == 1
    assert card.per_transform["substitution"].misses == 1


def test_counts_are_consistent(fixture_events, load_rule_text):
    card = run(load_rule_text("schtasks_create_literal.yml"), fixture_events)
    attacks = sum(e.label == "attack" for e in fixture_events)
    benign = sum(e.label == "benign" for e in fixture_events)
    assert card.hits + card.misses == attacks
    assert sum(b.benign for b in card.per_transform.values()) == benign
    assert len(card.matched_event_ids) == card.hits + card.false_alarms


def test_empty_event_list():
    card = run(make_rule("  sel:\n    Image: '*'\n  condition: sel"), [])
    assert card.valid and (card.hits, card.misses, card.false_alarms) == (0, 0, 0)


@pytest.mark.parametrize(
    ("rule_yaml", "error_fragment"),
    [
        ("title: [unclosed", "invalid YAML"),
        ("- just\n- a list", "single YAML mapping"),
        ("a: 1\n---\nb: 2", "invalid YAML"),
        (
            "title: no detection\nlogsource: {category: process_creation, product: windows}",
            "invalid Sigma rule",
        ),
        (make_rule("  sel:\n    Image: x\n  condition: sel and missing"), "condition"),
        (
            make_rule("  sel:\n    Image: x\n  condition: sel").replace("process_creation", "registry_set"),
            "logsource",
        ),
        ("x: '" + "a" * MAX_RULE_BYTES + "'", "exceeds"),
    ],
    ids=["bad-yaml", "not-mapping", "multi-doc", "no-detection", "bad-condition", "out-of-scope", "too-big"],
)
def test_invalid_rules_return_invalid_scorecard(rule_yaml, error_fragment):
    card = run(rule_yaml, [make_event()])
    assert not card.valid
    assert error_fragment in card.error
    assert (card.hits, card.misses, card.false_alarms, card.matched_event_ids) == (0, 0, 0, [])


def test_error_messages_do_not_leak_event_contents():
    secret = "HELDOUT-SECRET-CMDLINE"
    card = run(
        make_rule("  sel:\n    CommandLine|re: '('\n  condition: sel"), [make_event(command_line=secret)]
    )
    assert not card.valid and secret not in card.error


def test_duplicate_event_ids_raise():
    with pytest.raises(ValueError, match="duplicate"):
        run(make_rule("  sel:\n    Image: x\n  condition: sel"), [make_event(), make_event()])
