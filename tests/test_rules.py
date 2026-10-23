import json
from pathlib import Path

import pytest

from detectforge.cli import main
from detectforge.rules.convert import convert_rule
from detectforge.rules.parse import RuleError
from detectforge.rules.validate import validate_rule

from conftest import FIXTURES, make_rule

FIXTURE_RULES = sorted((FIXTURES / "rules").glob("*.yml"))


@pytest.mark.parametrize("path", FIXTURE_RULES, ids=lambda p: p.name)
def test_fixture_rules_are_valid(path: Path):
    result = validate_rule(path.read_text(encoding="utf-8"))
    assert result.valid, result.errors


def test_validate_reports_parse_errors():
    result = validate_rule(make_rule("  sel:\n    Image: x\n  condition: sel or nothing"))
    assert not result.valid and result.errors


def test_validate_warns_on_fields_outside_event_schema():
    result = validate_rule(make_rule("  sel:\n    User: 'SYSTEM'\n  condition: sel"))
    assert result.valid
    assert any("'User'" in w for w in result.warnings)


def test_validate_surfaces_pysigma_validator_issues():
    result = validate_rule(make_rule("  sel:\n    Image: x\n  unused:\n    Image: y\n  condition: sel"))
    assert any("unused" in w.lower() or "dangling" in w.lower() for w in result.warnings + result.errors)


def test_convert_to_lucene_uses_ecs_fields(load_rule_text):
    [query] = convert_rule(load_rule_text("certutil_download_literal.yml"), "lucene")
    assert "process.command_line" in query and "process.executable" in query


def test_convert_rejects_unknown_target(load_rule_text):
    with pytest.raises(ValueError, match="unknown target"):
        convert_rule(load_rule_text("certutil_download_literal.yml"), "splunk")


def test_convert_rejects_invalid_rule():
    with pytest.raises(RuleError):
        convert_rule("title: [", "lucene")


def test_cli_harness_prints_scorecard(capsys):
    code = main(["harness", str(FIXTURE_RULES[0]), str(FIXTURES / "events.jsonl")])
    card = json.loads(capsys.readouterr().out)
    assert code == 0 and card["valid"] and "per_transform" in card


def test_cli_validate_exit_code(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [", encoding="utf-8")
    assert main(["validate", str(bad)]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False
