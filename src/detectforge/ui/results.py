"""The evaluation's headline numbers, computed from the saved runs the same way as the report.

Home and the Lab show them; both must say exactly what the report says, so they share this one
function. The frozen result is the test split (techniques the prompts were never tuned on), runs
with the frozen prompts on the current tuning / held-out split, at the frozen model-call budget.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from detectforge.eval.arms import ArmResult
from detectforge.review import list_runs, load_run

FROZEN_PROMPTS = {"harden-v7", "write-v2"}
FROZEN_BUDGET = {"write": 15}
# The current split (substitution + reordering tuned; omission, insertion, recoding held out) dates
# from this change; older runs were scored on an earlier split.
SPLIT_SINCE = datetime(2026, 11, 21, 15, 13, 27, tzinfo=UTC)


@dataclass
class ArmNumbers:
    runs: int = 0
    rules: int = 0
    passed: int = 0
    approved: int = 0
    rejected: int = 0
    scored: int = 0  # runs whose rule has unseen variations
    before: float | None = None
    after: float | None = None
    new_false_alarm_runs: int = 0
    techniques: set[str] = field(default_factory=set)


@dataclass
class Headline:
    community_unseen: float | None = None  # Arm 1, test rules with unseen variations
    community_rules: int = 0
    community_scored: int = 0
    hardened: ArmNumbers = field(default_factory=ArmNumbers)
    written: ArmNumbers = field(default_factory=ArmNumbers)


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def headline(data_dir: Path, runs_dir: Path) -> Headline:
    out = Headline()
    try:
        selection = yaml.safe_load((data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return out
    rules = selection.get("rules", [])
    dev = {r["technique"] for r in rules if r.get("split") == "dev"}
    test_ids = {r["id"] for r in rules if r.get("split") == "test"}

    try:
        arm1 = ArmResult.model_validate_json(
            (data_dir / "eval" / "results" / "arm1_community.json").read_text("utf-8")
        )
        test_rules = [r for r in arm1.rules if r.rule_id in test_ids]
        unseen = [r.resistance_by_mutation_split.get("heldout") for r in test_rules]
        unseen = [u for u in unseen if u is not None]
        out.community_rules, out.community_scored = len(test_rules), len(unseen)
        out.community_unseen = _mean(unseen)
    except (OSError, ValidationError):
        pass

    befores: dict[str, list[float]] = {"harden": [], "write": []}
    afters: dict[str, list[float]] = {"harden": [], "write": []}
    for s in list_runs(runs_dir):
        if s.prompt_version not in FROZEN_PROMPTS or s.created < SPLIT_SINCE or s.technique in dev:
            continue
        outcome = load_run(runs_dir, s.trace_id)
        run = outcome.run
        if run.model_calls and not run.model_calls[-1].ok:
            continue  # lost to a model outage, redone by the batch
        prov = outcome.provenance
        if s.mode in FROZEN_BUDGET and prov and prov.budgets.get("model_calls") != FROZEN_BUDGET[s.mode]:
            continue  # an ablation, reported apart
        arm = out.hardened if s.mode == "harden" else out.written
        arm.runs += 1
        arm.techniques.add(s.technique)
        arm.passed += s.status == "passed"
        decision = s.decision.decision if s.decision else None
        arm.approved += decision == "approved"
        arm.rejected += decision == "rejected"
        heldout = outcome.heldout_evaluation
        arm.new_false_alarm_runs += bool(heldout and heldout.new_false_alarm_event_ids)
        if s.heldout_mutations:
            arm.scored += 1
            befores[s.mode].append(s.heldout_before or 0.0)
            afters[s.mode].append(s.heldout_after or 0.0)
    for mode, arm in (("harden", out.hardened), ("write", out.written)):
        arm.before, arm.after = _mean(befores[mode]), _mean(afters[mode])
        arm.rules = len(arm.techniques)
    return out
