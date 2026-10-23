"""convert_rule: translate a Sigma rule into a SIEM query with pySigma backends."""

from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
from sigma.exceptions import SigmaError
from sigma.pipelines.elasticsearch import ecs_windows

from detectforge.rules.parse import RuleError, load_rule

TARGETS = {"lucene": LuceneBackend, "eql": EqlBackend}


def convert_rule(rule_yaml: str, target: str = "lucene") -> list[str]:
    """Return the backend queries for the rule (Elastic Common Schema field names)."""
    if target not in TARGETS:
        raise ValueError(f"unknown target {target!r}; choose from {sorted(TARGETS)}")
    rule = load_rule(rule_yaml)
    backend = TARGETS[target](processing_pipeline=ecs_windows())
    try:
        return backend.convert_rule(rule)
    except SigmaError as e:
        raise RuleError(f"conversion to {target} failed: {e}") from e
