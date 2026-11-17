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


class _NoDuplicateKeysLoader(yaml.SafeLoader):
    """safe_load, except a key repeated in one mapping is an error.

    Plain YAML keeps only the last of two equal keys, so two `CommandLine|re:` lines in one selection
    silently become one: a dev run "passed" with its `add` check dropped, and the YAML a reviewer read
    still showed both lines. pySigma reads rules the same way, so the deployed rule would match too much.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise RuleError(
                    f"duplicate key {key!r} on line {key_node.start_mark.line + 1}: YAML keeps only the "
                    "last one, so the earlier condition would be silently dropped. Put the conditions in "
                    "separate selections and combine them in the condition (e.g. 'sel_a and sel_b')."
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_rule(rule_yaml: str) -> SigmaRule:
    """Parse exactly one Sigma rule for Windows process creation, or raise RuleError."""
    if len(rule_yaml.encode("utf-8")) > MAX_RULE_BYTES:
        raise RuleError(f"rule exceeds {MAX_RULE_BYTES} bytes")
    try:
        doc = yaml.load(rule_yaml, Loader=_NoDuplicateKeysLoader)  # a SafeLoader: no Python objects
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
