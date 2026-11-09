"""validate_rule: is a rule parseable, in scope, evaluable by the harness, and well-formed?"""

from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssue, SigmaValidationIssueSeverity
from sigma.validators.core import validators as core_validators

from detectforge.harness.matcher import can_fire, compile_rule, rule_fields
from detectforge.rules.parse import RuleError, load_rule
from detectforge.schemas import SIGMA_FIELD_MAP, ValidationResult

# Skipped: file-name and cross-rule checks (meaningless for a single YAML string), and the
# ATT&CK/D3FEND tag checks, which download MITRE data at runtime and would make validation
# depend on the network.
_SKIPPED_VALIDATORS = {
    "duplicate_filename",
    "filename_length",
    "duplicate_title",
    "duplicate_references",
    "attacktag",
    "d3_fendtag",
}
_VALIDATORS = [v for name, v in core_validators.items() if name not in _SKIPPED_VALIDATORS]


def validate_rule(rule_yaml: str) -> ValidationResult:
    try:
        rule = load_rule(rule_yaml)
        compile_rule(rule)
        missing = sorted(rule_fields(rule) - SIGMA_FIELD_MAP.keys())
        fires = can_fire(rule)
    except RuleError as e:
        return ValidationResult(valid=False, errors=[str(e)])

    validator = SigmaValidator(_VALIDATORS)
    issues = validator.validate_rule(rule) + validator.finalize()
    errors = [_describe(i) for i in issues if i.severity == SigmaValidationIssueSeverity.HIGH]
    warnings = [_describe(i) for i in issues if i.severity != SigmaValidationIssueSeverity.HIGH]
    if missing:
        names = ", ".join(f"'{f}'" for f in missing)
        if fires:
            warnings.append(
                f"fields {names} are not in the event schema and never match; harmless here, the rule "
                "can still match through other fields, but it loses whatever those checks detect"
            )
        else:
            errors.append(
                f"rule can never fire on our events: it depends on fields {names}, which are not in "
                f"the event schema ({', '.join(SIGMA_FIELD_MAP)})"
            )
    return ValidationResult(valid=not errors, errors=errors, warnings=warnings)


def _describe(issue: SigmaValidationIssue) -> str:
    return f"{type(issue).__name__}: {issue.description}"
