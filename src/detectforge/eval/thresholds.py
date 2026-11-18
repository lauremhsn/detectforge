"""Gate threshold ablation: how the results depend on the 80% evasion-resistance minimum.

Recomputed from saved runs, at no model cost. For each threshold, a run's final rule "passes" if
every blocking gate check other than evasion_resistance passed and its tuning evasion resistance is
at least the threshold. Then: how many pass, and how the passing rules do on held-out data.

Post hoc only: with a different threshold the agent would have seen different gate feedback and
might have stopped earlier or kept going, so this shows which of the rules it actually produced
clear each bar, not what it would have produced. Only runs where the agent proposed a rule count
(final_source accepted or best_attempt); runs that kept the original or produced nothing don't.
"""

from pathlib import Path

from pydantic import BaseModel

from detectforge.review import latest_prompt_versions, list_runs, load_run

DEFAULT_THRESHOLDS = (0.6, 0.7, 0.8, 0.9, 1.0)
PROPOSED = ("accepted", "best_attempt")


class ThresholdRow(BaseModel):
    mode: str
    prompt_version: str
    threshold: float
    runs: int  # runs where the agent proposed a rule
    passing: int
    passing_with_heldout: int  # of those, rules with held-out mutations (the others are n/a)
    heldout_after_mean: float | None  # over passing rules with held-out mutations
    passing_with_new_heldout_false_alarms: int  # passing rules that alarm on held-out benign events


class _Run(BaseModel):
    mode: str
    prompt_version: str
    tuning_after: float | None
    other_checks_pass: bool
    heldout_mutations: int
    heldout_after: float | None
    new_heldout_false_alarms: int


def _passes(run: _Run, threshold: float) -> bool:
    # Same rule as the gate: no mutated tuning attacks to measure means the check can't fail.
    resistance_ok = run.tuning_after is None or run.tuning_after >= threshold
    return run.other_checks_pass and resistance_ok


def threshold_table(
    runs_dir: Path, thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS, current_prompts_only: bool = True
) -> list[ThresholdRow]:
    summaries = list_runs(runs_dir)
    if current_prompts_only:
        current = latest_prompt_versions(summaries)
        summaries = [s for s in summaries if s.prompt_version in current]
    runs = []
    for s in summaries:
        outcome = load_run(runs_dir, s.trace_id)
        run, heldout = outcome.run, outcome.heldout_evaluation
        if run.final_source not in PROPOSED:
            continue
        others = [c for c in run.gate.checks if c.blocking and c.name != "evasion_resistance"]
        runs.append(
            _Run(
                mode=run.mode,
                prompt_version=run.prompt_version,
                tuning_after=run.tuning_evasion_resistance_after,
                other_checks_pass=all(c.passed for c in others),
                heldout_mutations=heldout.mutated_attacks if heldout else 0,
                heldout_after=heldout.evasion_resistance_after if heldout else None,
                new_heldout_false_alarms=len(heldout.new_false_alarm_event_ids) if heldout else 0,
            )
        )

    rows = []
    for mode, version in sorted({(r.mode, r.prompt_version) for r in runs}):
        group = [r for r in runs if (r.mode, r.prompt_version) == (mode, version)]
        for threshold in thresholds:
            passing = [r for r in group if _passes(r, threshold)]
            scored = [r for r in passing if r.heldout_mutations > 0]
            rows.append(
                ThresholdRow(
                    mode=mode,
                    prompt_version=version,
                    threshold=threshold,
                    runs=len(group),
                    passing=len(passing),
                    passing_with_heldout=len(scored),
                    # A rule that couldn't be evaluated detects nothing: 0, never dropped.
                    heldout_after_mean=(
                        sum(r.heldout_after or 0.0 for r in scored) / len(scored) if scored else None
                    ),
                    passing_with_new_heldout_false_alarms=sum(
                        r.new_heldout_false_alarms > 0 for r in passing
                    ),
                )
            )
    return rows
