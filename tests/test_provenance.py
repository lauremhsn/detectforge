"""Provenance and quota saving: same setup is never paid for twice; the batch respects a call cap."""

from datetime import UTC, datetime

import pytest
from test_agent_loop import ScriptedClient, tool_call
from test_batch import setup  # noqa: F401  (pytest fixture)

from detectforge.agent.batch import harden_selection
from detectforge.config import get_settings
from detectforge.llm import LLMError, key_info
from detectforge.provenance import code_fingerprint, events_fingerprint, make_provenance
from detectforge.review import calls_today


def provenance(rule, events, **overrides):
    args = {"model": "m", "fallback_model": None, "prompt_version": "harden-v5", "settings": get_settings()}
    return make_provenance(rule, events, **{**args, **overrides})


def test_setup_key_changes_with_anything_that_can_change_the_result(fixture_events, load_rule_text):
    rule = load_rule_text("schtasks_create_literal.yml")
    base = provenance(rule, fixture_events)
    assert base.setup_key == provenance(rule, list(reversed(fixture_events))).setup_key  # order-free
    assert base.setup_key == provenance(rule.replace("\n", "\r\n"), fixture_events).setup_key  # CRLF
    changed = [
        provenance(rule, fixture_events, model="other"),
        provenance(rule, fixture_events, prompt_version="harden-v6"),
        provenance(rule, fixture_events[1:]),
        provenance(rule + "\n# edited", fixture_events),
        provenance(rule, fixture_events, settings=get_settings().model_copy(update={"max_model_calls": 3})),
    ]
    assert all(p.setup_key != base.setup_key for p in changed)
    # The commit is for humans only: a docs-only commit must not invalidate earlier runs.
    assert base.model_copy(update={"git_commit": "abc", "git_dirty": True}).setup_key == base.setup_key


def test_fingerprints_are_stable(fixture_events, tmp_path):
    assert events_fingerprint(fixture_events) == events_fingerprint(list(fixture_events))
    pkg = tmp_path / "pkg"
    (pkg / "ui").mkdir(parents=True)
    (pkg / "gate.py").write_bytes(b"x = 1\r\n")
    first = code_fingerprint(pkg)
    (pkg / "ui" / "app.py").write_text("display only")  # UI code can't change a result
    assert code_fingerprint(pkg) == first
    (pkg / "gate.py").write_bytes(b"x = 1\n")  # same code, Linux line endings
    assert code_fingerprint(pkg) == first
    (pkg / "gate.py").write_text("x = 2\n")
    assert code_fingerprint(pkg) != first


def test_reporting_files_are_left_out_by_path_not_folder(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "eval").mkdir(parents=True)
    (pkg / "harness").mkdir()
    (pkg / "harness" / "compare.py").write_text("scores = 1\n")
    first = code_fingerprint(pkg)
    for name in ("arms", "metrics", "regression", "export", "thresholds"):
        (pkg / "eval" / f"{name}.py").write_text("scores saved runs after the fact")
    assert code_fingerprint(pkg) == first  # rescoring a corpus never orphans it
    (pkg / "eval" / "arms.py").write_text("scores = 2\n")
    assert code_fingerprint(pkg) == first
    (pkg / "harness" / "compare.py").write_text("scores = 2\n")  # what the agent sees and a run saves
    second = code_fingerprint(pkg)
    assert second != first
    (pkg / "export.py").write_text("x")  # the name alone isn't enough: only eval/export.py is out
    assert code_fingerprint(pkg) != second


def test_nothing_on_the_run_path_imports_the_reporting_files():
    """The files left out of the fingerprint must not affect a run, so no run code may import them."""
    import ast

    import detectforge.provenance as prov

    package = prov.PACKAGE_DIR
    excluded = {p.removesuffix(".py").replace("/", ".") for p in prov._NOT_RESULT_FILES}
    for path in package.rglob("*.py"):
        relative = path.relative_to(package).as_posix()
        if relative == "cli.py" or relative in prov._NOT_RESULT_FILES or relative.startswith("ui/"):
            continue  # the CLI only calls them for its report commands; the UI is left out already
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            n.module.removeprefix("detectforge.")
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module
        } | {
            a.name.removeprefix("detectforge.")
            for n in ast.walk(tree)
            if isinstance(n, ast.Import)
            for a in n.names
        }
        assert not imported & excluded, f"{relative} imports reporting code left out of the fingerprint"


def test_rerunning_a_batch_reuses_runs_with_the_same_setup(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, robust = setup
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="verb")])
    first = harden_selection(selection[:1], fixture_events, index, client, "fake", tmp_path)
    assert first[0].action == "hardened" and first[0].model_calls == 1

    again = ScriptedClient([])  # would fail if called
    second = harden_selection(selection[:1], fixture_events, index, again, "fake", tmp_path)
    assert second[0].action == "reused" and second[0].model_calls == 0 and not again.requests
    assert second[0].status == "passed" and second[0].trace_id == first[0].trace_id

    other_model = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="verb")])
    third = harden_selection(selection[:1], fixture_events, index, other_model, "other", tmp_path)
    assert third[0].action == "hardened"  # a different setup is a new experiment


def test_repeat_only_runs_what_is_missing(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, robust = setup
    submit = tool_call("submit", rule_yaml=robust, rationale="verb")
    harden_selection(selection[:1], fixture_events, index, ScriptedClient([submit]), "fake", tmp_path)
    client = ScriptedClient([submit, submit])
    items = harden_selection(selection[:1], fixture_events, index, client, "fake", tmp_path, repeat=3)
    assert [i.action for i in items] == ["reused", "hardened", "hardened"]
    assert len(client.requests) == 2


def test_runs_cut_short_by_the_model_are_not_reused(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, robust = setup
    harden_selection(
        selection[:1], fixture_events, index, ScriptedClient([LLMError("429")]), "fake", tmp_path
    )
    client = ScriptedClient([tool_call("submit", rule_yaml=robust, rationale="verb")])
    items = harden_selection(selection[:1], fixture_events, index, client, "fake", tmp_path)
    assert items[0].action == "hardened"


def test_max_calls_only_starts_runs_whose_whole_budget_fits(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, robust = setup
    settings = get_settings().model_copy(update={"max_model_calls": 10})
    submit = tool_call("submit", rule_yaml=robust, rationale="verb")
    items = harden_selection(
        selection[:1],
        fixture_events,
        index,
        ScriptedClient([submit, submit]),
        "fake",
        tmp_path,
        repeat=3,
        max_calls=11,
        settings=settings,
    )
    # Each run spends 1 call: after the first, 10 of 11 are left, so a second full budget still fits
    # (regression: the cap used to count every run's whole budget, skipping runs that would fit).
    assert [i.action for i in items] == ["hardened", "hardened", "skipped"]
    assert "only 9 of --max-calls 11 left" in items[2].note


def test_dry_run_needs_no_model_and_spends_nothing(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, _ = setup
    items = harden_selection(
        selection, fixture_events, index, None, "fake", tmp_path, dry_run=True, rule_ids={"weak-schtasks"}
    )
    assert [(i.rule_id, i.action) for i in items] == [("weak-schtasks", "planned")]
    assert not list(tmp_path.glob("*.json"))
    with pytest.raises(ValueError, match="dry_run"):
        harden_selection(selection, fixture_events, index, None, "fake", tmp_path)


def test_calls_today_counts_only_todays_runs(setup, fixture_events, tmp_path):  # noqa: F811
    index, selection, robust = setup
    client = ScriptedClient(
        [tool_call("run_tuning_set", rule_yaml=robust), tool_call("submit", rule_yaml=robust)]
    )
    harden_selection(selection[:1], fixture_events, index, client, "fake", tmp_path)
    assert calls_today(tmp_path) == len(client.requests) > 0
    assert calls_today(tmp_path, now=datetime(2000, 1, 1, tzinfo=UTC)) == 0


def test_key_info_never_leaks_the_key(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("connection refused for Bearer sk-secret")

    monkeypatch.setattr("urllib.request.urlopen", fail)
    with pytest.raises(LLMError) as e:
        key_info("https://openrouter.ai/api/v1", "sk-secret")
    assert "sk-secret" not in str(e.value)
    with pytest.raises(LLMError, match="only available for OpenRouter"):
        key_info("http://localhost:11434/v1", "x")
