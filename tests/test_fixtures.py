"""Sanity checks on the fixture dataset itself."""

from collections import Counter

from detectforge.harness import run


def test_fixture_size_and_balance(fixture_events):
    assert 10 <= len(fixture_events) <= 20
    labels = Counter(e.label for e in fixture_events)
    assert labels["attack"] and labels["benign"]


def test_every_mutation_points_at_an_unmutated_attack(fixture_events):
    by_id = {e.event_id: e for e in fixture_events}
    for e in fixture_events:
        if e.transform != "none":
            base = by_id[e.base_id]
            assert base.transform == "none" and base.technique == e.technique and base.label == e.label


def test_split_is_by_transform_type(fixture_events):
    """Held-out mutations use transform types never seen in tuning (CLAUDE.md section 4)."""
    tune = {e.transform for e in fixture_events if e.split == "tune" and e.transform != "none"}
    heldout = {e.transform for e in fixture_events if e.split == "heldout" and e.transform != "none"}
    assert tune and heldout and not tune & heldout


def test_hard_negatives_trigger_a_community_style_rule(fixture_events, load_rule_text):
    """Week-1 check: hard negatives must be hard enough to cause some false alarms."""
    card = run(load_rule_text("schtasks_create_literal.yml"), fixture_events)
    assert card.false_alarms > 0
