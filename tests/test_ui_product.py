"""The product flows: coverage at a glance, "is this threat covered?", guided jumps, report, operations."""

import json

import pytest

pytest.importorskip("streamlit")
import yaml
from test_batch import reference
from test_ui import _saved_run, data_dir, open_app, unescaped  # noqa: F401  (data_dir is a fixture)

from detectforge.reference.index import INDEX_FORMAT, ReferenceIndex
from detectforge.ui.coverage_page import coverage_report, coverage_rows, tactics_of
from detectforge.ui.request_page import assess

TECHNIQUE = "T1053.005"


@pytest.fixture
def rules(load_rule_text):
    return {
        "literal": load_rule_text("schtasks_create_literal.yml"),
        "robust": load_rule_text("schtasks_create_robust.yml"),
    }


@pytest.fixture
def with_index(data_dir, rules):  # noqa: F811
    """A small SigmaHQ index on disk: one evadable schtasks rule; for T1490 only a rule that can't fire."""
    index_dir = data_dir / "sigmahq"
    index_dir.mkdir()
    rule = reference("literal-schtasks", rules["literal"], TECHNIQUE).model_copy(
        update={"title": "Scheduled Task Creation Via Schtasks"}
    )
    unusable = reference("vss", rules["literal"], "T1490").model_copy(
        update={"title": "Shadow Copies Deletion Using Vssadmin", "can_fire": False}
    )
    lines = [rule.model_dump_json(), unusable.model_dump_json()]
    (index_dir / "index.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    meta = {"format": INDEX_FORMAT, "release": "test"}
    (index_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return data_dir


# ---- "a new threat came in: are we covered?" ---------------------------------------------------


def test_coverage_verdicts_come_from_the_harness_not_the_model(rules, fixture_events):
    index = ReferenceIndex(
        [
            reference("literal", rules["literal"], TECHNIQUE),
            reference("robust-t1105", rules["robust"], "T1105"),
        ]
    )
    evadable = assess(TECHNIQUE, index, fixture_events)
    assert evadable.verdict == "evadable" and evadable.rule_id == "literal"
    assert evadable.detected < evadable.attacks and "substitution" in evadable.evaded_by

    assert assess("T1490", index, fixture_events).verdict == "not_covered"
    assert assess("T1105", index, fixture_events).verdict in {"untested", "robust", "evadable"}
    no_attacks = [e for e in fixture_events if e.technique != "T1105"]
    assert assess("T1105", index, no_attacks).verdict == "untested"  # rule exists, nothing to test it on


def test_a_technique_is_judged_by_its_strongest_rule_not_the_first_one_found(rules, fixture_events):
    """Regression: the verdict used the first search hit, which on real data caught 0 of 23 attacks."""
    weak = reference("weak-first", rules["literal"], TECHNIQUE)
    strong = reference("strong-second", rules["robust"], TECHNIQUE)
    other = reference("other-technique", rules["robust"], "T1105")  # not tagged with this technique
    c = assess(TECHNIQUE, ReferenceIndex([weak, strong, other]), fixture_events)
    assert c.rule_id == "strong-second" and c.usable_rules == 2
    assert c.detected == c.attacks and c.detected_together == c.attacks


def test_a_pasted_request_gets_a_verdict_and_harden_opens_the_rule(with_index):
    at = open_app("request")
    at.text_area(key="intake_request").set_value("detect scheduled task persistence with schtasks").run()
    next(b for b in at.button if b.label == "Check coverage").click().run()
    assert not at.exception
    page = unescaped(" ".join(m.value for m in at.markdown))
    assert f"{TECHNIQUE} — covered, but evadable" in page and "evaded by" in page

    next(b for b in at.button if b.label == "Harden it →").click().run()
    assert at.session_state["page"] == "rules" and at.radio(key="rules_step").value == "harden"
    assert any(
        "Scheduled Task Creation Via Schtasks" in unescaped(i.value) for i in at.info
    )  # rule under test


def test_an_uncovered_technique_offers_to_write_a_rule(with_index):
    """T1490 has only a rule that can never fire, so it isn't covered: the agent should write one."""
    at = open_app("request")
    at.text_area(key="intake_request").set_value("shadow copies deletion vssadmin").run()
    next(b for b in at.button if b.label == "Check coverage").click().run()
    assert not at.exception
    page = unescaped(" ".join(m.value for m in at.markdown))
    assert "T1490 — not covered" in page
    write = next(b for b in at.button if b.label == "Ask the agent to write a rule for T1490")
    assert write.disabled  # agent runs are off in tests
    assert any("detectforge write --technique T1490" in c.value for c in at.caption)


# ---- coverage dashboard -----------------------------------------------------------------------


@pytest.fixture
def evaluated(data_dir, rules, load_rule_text, fixture_events):  # noqa: F811
    """A one-rule evaluation selection with Arm 1 results, and one hardening run of that rule."""
    from detectforge.eval.arms import run_community_arm

    eval_dir = data_dir / "eval"
    (eval_dir / "results").mkdir(parents=True)
    base = [e.event_id for e in fixture_events if e.technique == TECHNIQUE and e.transform == "none"]
    selection = {
        "rules": [
            {"id": "literal-schtasks", "title": "Literal schtasks", "technique": TECHNIQUE, "split": "dev",
             "base_attacks": base},
        ]
    }  # fmt: skip
    (eval_dir / "selection.yml").write_text(yaml.safe_dump(selection), encoding="utf-8")
    index = ReferenceIndex([reference("literal-schtasks", rules["literal"], TECHNIQUE)])
    arm = run_community_arm(selection, index, fixture_events)
    (eval_dir / "results" / "arm1_community.json").write_text(arm.model_dump_json(), encoding="utf-8")
    _saved_run(data_dir / "runs", load_rule_text, fixture_events)  # hardens the literal rule
    return data_dir


def test_coverage_rows_link_each_rule_to_its_score_and_its_agent_run(evaluated, rules):
    rows = coverage_rows(
        evaluated / "eval" / "selection.yml",
        evaluated / "eval" / "results" / "arm1_community.json",
        evaluated / "runs",
        {"literal-schtasks": rules["literal"].replace("\n", "\r\n")},  # line endings don't matter
    )
    (row,) = rows
    assert row.community is not None and row.community < 1 and "substitution" in row.evaded_by
    assert row.hardened is not None and row.hardened.decision == "pending review"
    assert row.hardened.heldout_after == 1.0 and row.written is None
    assert row.tactics == ["persistence"]

    report = coverage_report(rows)
    assert report.startswith("# DetectForge coverage report") and "Literal schtasks" in report
    assert "pending review" in report


def test_tactics_come_from_the_rule_tags():
    tags = ["attack.persistence", "attack.privilege_escalation", "attack.t1053.005", "attack.g0016"]
    rule = yaml.safe_dump({"tags": tags})
    assert tactics_of(rule) == ["persistence", "privilege-escalation"]
    assert tactics_of("not: [valid") == [] and tactics_of(None) == []


def test_home_guides_people_to_each_job(evaluated, with_index):
    at = open_app("coverage")
    assert not at.exception
    assert any("1 proposal waiting" in c.value for c in at.caption)
    assert at.radio(key="page").options[2].endswith("(1)")  # pending count on the top bar
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Rules evaded as published"] == "1/1" and metrics["Hardened by the agent"] == "1"

    next(b for b in at.button if b.label == "Open the review queue →").click().run()
    assert at.session_state["page"] == "review" and not at.exception


def test_agent_operations_summarises_runs(evaluated):
    at = open_app("operations")
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Agent runs"] == "1" and metrics["Passed the gate"] == "1/1"
    assert metrics["Model calls"] == "2"


def test_coverage_chart_compares_the_same_rule_before_and_after_on_held_out(evaded_rows):
    from detectforge.ui.coverage_page import AFTER, BEFORE, heldout_mean, resistance_chart

    chart = resistance_chart({TECHNIQUE: evaded_rows})
    series = {v["series"]: v["resistance"] for v in chart["data"]["values"]}
    cell = evaded_rows[0].hardened
    assert series == {BEFORE: cell.heldout_before, AFTER: cell.heldout_after} and series[AFTER] == 1.0
    mean = heldout_mean(evaded_rows)
    assert (mean.hardened, mean.with_heldout, mean.after) == (1, 1, 1.0)


def test_a_rule_without_held_out_mutations_is_n_a_not_a_score(evaded_rows):
    from detectforge.ui.coverage_page import _run_text, heldout_mean, resistance_chart

    no_heldout = evaded_rows[0].model_copy(
        update={"hardened": evaded_rows[0].hardened.model_copy(update={"heldout_mutations": 0})}
    )
    assert resistance_chart({TECHNIQUE: [no_heldout]}) is None  # nothing to compare on held-out
    assert _run_text(no_heldout.hardened).startswith("n/a (no held-out mutations)")
    mean = heldout_mean([*evaded_rows, no_heldout])
    assert (mean.hardened, mean.with_heldout, mean.after) == (2, 1, 1.0)  # left out, not averaged as 0
    report = coverage_report([no_heldout])
    assert "n/a (no held-out mutations)" in report and "mean over the 0 hardened rules" in report


@pytest.fixture
def evaded_rows(evaluated, rules):
    return coverage_rows(
        evaluated / "eval" / "selection.yml",
        evaluated / "eval" / "results" / "arm1_community.json",
        evaluated / "runs",
        {"literal-schtasks": rules["literal"]},
    )
