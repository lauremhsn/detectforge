"""Metadata of an agent-written rule, set by code instead of trusting what the model typed.

Found on a real run: a written rule came back with a made-up id, author "Detection Engineer" and the
date 2024-01-15. An id copied or invented by the model can collide with a SigmaHQ rule's, so the id
is derived from the run's trace id (the same run always gets the same id), and author, date and
status say what the rule is: new, agent-written, not yet battle-tested. Only top-level metadata lines
are replaced; the detection logic is left byte for byte as the agent wrote it (and the quality gate
checked it).
"""

import uuid
from datetime import date

import yaml

from detectforge.rules.validate import validate_rule

AUTHOR = "DetectForge (agent-written, human-reviewed before deployment)"
STATUS = "experimental"  # Sigma's status for a new rule that hasn't been tested in production
STAMPED = ("id", "status", "author", "date")
_NAMESPACE = uuid.UUID("6d1f3b8e-2c4a-4e5f-9a7b-0c1d2e3f4a5b")  # fixed, so ids are reproducible


def rule_id(trace_id: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, trace_id))


def stamp_written_rule(rule_yaml: str, trace_id: str, today: date) -> str:
    """The rule with id, status, author and date set; unchanged if it can't be stamped safely."""
    try:
        before = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        return rule_yaml
    if not isinstance(before, dict) or "logsource" not in before:
        return rule_yaml

    values = {"id": rule_id(trace_id), "status": STATUS, "author": AUTHOR, "date": today.isoformat()}
    lines = {key: f"{key}: {yaml.safe_dump(values[key]).splitlines()[0]}" for key in STAMPED}
    kept, skipping, placed = [], False, set()
    for line in rule_yaml.splitlines():
        if line and not line[0].isspace() and not line.startswith(("#", "- ")):  # a top-level key
            key = line.split(":", 1)[0].strip().strip("\"'")
            skipping = key in STAMPED
            if skipping and key not in placed:  # replaced where it was (with its continuation lines)
                kept.append(lines[key])
                placed.add(key)
        if not skipping:
            kept.append(line)
    at = next((i for i, line in enumerate(kept) if line.startswith("logsource:")), None)
    if at is None:
        return rule_yaml
    missing = [lines[key] for key in STAMPED if key not in placed]
    stamped = "\n".join(kept[:at] + missing + kept[at:]) + ("\n" if rule_yaml.endswith("\n") else "")

    try:
        after = yaml.safe_load(stamped)
    except yaml.YAMLError:
        return rule_yaml
    unchanged = {k: v for k, v in before.items() if k not in STAMPED}
    if {k: v for k, v in after.items() if k not in STAMPED} != unchanged:
        return rule_yaml  # never risk changing anything but the metadata
    if any(str(after.get(k)) != values[k] for k in STAMPED) or not validate_rule(stamped).valid:
        return rule_yaml
    return stamped
