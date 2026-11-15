"""Parse untrusted Sigma rule YAML into a pySigma rule, enforcing project scope."""

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

MAX_RULE_BYTES = 64 * 1024
QUOTE_HINT = (
    r" (hint: YAML has no \' escape; inside a single-quoted value write a quote as '' (two single "
    r"""quotes), e.g. '[\s"'']' for a space, double or single quote)"""
)
SCOPE_CATEGORY = "process_creation"
SCOPE_PRODUCT = "windows"


class RuleError(ValueError):
    """A rule cannot be parsed, is out of scope, or cannot be evaluated."""


def load_rule(rule_yaml: str) -> SigmaRule:
    """Parse exactly one Sigma rule for Windows process creation, or raise RuleError."""
    if len(rule_yaml.encode("utf-8")) > MAX_RULE_BYTES:
        raise RuleError(f"rule exceeds {MAX_RULE_BYTES} bytes")
    try:
        doc = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        hint = QUOTE_HINT if "\\'" in rule_yaml else ""  # the classic regex-in-YAML mistake
        raise RuleError(f"invalid YAML: {e}{hint}") from e
    if not isinstance(doc, dict):
        raise RuleError("rule must be a single YAML mapping")
    try:
        rule = SigmaRule.from_dict(doc)
    except SigmaError as e:
        raise RuleError(f"invalid Sigma rule: {e}") from e

    category, product = rule.logsource.category, rule.logsource.product
    if category != SCOPE_CATEGORY or product != SCOPE_PRODUCT:
        raise RuleError(
            f"logsource must be category={SCOPE_CATEGORY}, product={SCOPE_PRODUCT}; "
            f"got category={category}, product={product}"
        )
    return rule
