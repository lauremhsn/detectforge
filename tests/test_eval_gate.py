"""CI evaluation gate: recomputed Arm 1 results must match the committed ones, or the change is named."""

import pytest
import yaml
from test_eval import EVENTS, LITERAL, ROBUST, _ref

from detectforge import cli
from detectforge.eval.arms import run_community_arm
from detectforge.eval.regression import diff_arm_results
from detectforge.events import dump_events
from detectforge.reference.index import ReferenceIndex

SELECTION = {
    "rules": [
        {"id": "r1", "title": "literal", "technique": "T1053.005", "split": "test", "base_attacks": ["b01"]},
        {"id": "r2", "title": "robust", "technique": "T1053.005", "split": "dev", "base_attacks": ["b01"]},
    ]
}


def arm(literal=LITERAL):
    return run_community_arm(
        SELECTION, ReferenceIndex([_ref("r1", literal), _ref("r2", ROBUST)], "t"), EVENTS
    )


def test_identical_results_and_float_noise_pass():
    expected = arm()
    assert diff_arm_results(expected, arm()) == []
    noisy = expected.model_copy(
        update={"overall_evasion_resistance": expected.overall_evasion_resistance + 1e-12}
    )
    assert diff_arm_results(expected, noisy) == []


def test_a_rule_that_detects_differently_is_named_with_its_numbers():
    """E.g. a matcher change makes the literal rule catch the substitution it used to miss."""
    changed = arm(literal=ROBUST)
    diffs = diff_arm_results(arm(), changed)
    assert "overall_evasion_resistance: 0.75 -> 1.0" in diffs
    assert "rules[r1].evasion_resistance: 0.5 -> 1.0" in diffs
    assert "rules[r1].resistance_by_transform.substitution: 0.0 -> 1.0" in diffs
    assert not any(d.startswith("rules[r2]") for d in diffs)  # the unchanged rule isn't reported


def test_added_or_dropped_rules_are_reported():
    full = arm()
    only_r2 = full.model_copy(update={"rules": full.rules[1:]})
    assert "rules[r1]: missing from the recomputed results" in diff_arm_results(full, only_r2)
    assert "rules[r1]: new, not in the committed results" in diff_arm_results(only_r2, full)


@pytest.fixture
def eval_dir(tmp_path, monkeypatch):
    from detectforge.config import get_settings

    data = tmp_path / "data"
    (data / "eval" / "results").mkdir(parents=True)
    (data / "eval" / "selection.yml").write_text(yaml.safe_dump(SELECTION), encoding="utf-8")
    dump_events([e for e in EVENTS if e.transform == "none"], data / "eval" / "base_events.jsonl")
    dump_events([e for e in EVENTS if e.transform != "none"], data / "eval" / "mutations.jsonl")
    monkeypatch.setenv("DETECTFORGE_DATA_DIR", str(data))
    get_settings.cache_clear()
    yield data
    get_settings.cache_clear()


def test_cli_check_passes_on_committed_results_and_fails_on_a_change(eval_dir, monkeypatch, capsys):
    index = ReferenceIndex([_ref("r1", LITERAL), _ref("r2", ROBUST)], "t")
    monkeypatch.setattr(cli.ReferenceIndex, "load", staticmethod(lambda path: index))
    results = eval_dir / "eval" / "results" / "arm1_community.json"

    assert cli.main(["eval", "community"]) == 0  # writes the results, as committed
    written = results.read_text(encoding="utf-8")
    assert cli.main(["eval", "community", "--check"]) == 0
    assert results.read_text(encoding="utf-8") == written  # --check never rewrites them

    changed = ReferenceIndex([_ref("r1", ROBUST), _ref("r2", ROBUST)], "t")
    monkeypatch.setattr(cli.ReferenceIndex, "load", staticmethod(lambda path: changed))
    capsys.readouterr()
    assert cli.main(["eval", "community", "--check"]) == 1
    err = capsys.readouterr().err
    assert "Arm 1 results changed" in err and "rules[r1].evasion_resistance: 0.5 -> 1.0" in err
    assert "commit the new results" in err
