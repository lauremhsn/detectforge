"""GitHub Actions workflow files must be valid YAML.

Regression: a step named "Upload coverage to Codecov (public repo: no token needed)" made ci.yml
invalid (": " starts a mapping), so GitHub ran no CI job at all, on main and on every pull request,
and reported only "workflow file issue". A broken workflow file now fails here instead.
"""

from pathlib import Path

import pytest
import yaml

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))


def test_there_are_workflows():
    assert WORKFLOWS


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_is_valid_yaml_with_jobs(path):
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict) and workflow.get("jobs"), f"{path.name} has no jobs"
    for name, job in workflow["jobs"].items():
        assert job.get("steps") or job.get("uses"), f"{path.name}: job {name} has no steps"
