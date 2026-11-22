"""Inter-rater agreement on rule approval: two reviewers rate the same runs blind, then compare.

Human review is one of DetectForge's evaluation methods, so its consistency has to be measured:
if two reviewers applying the same rubric disagree often, the rubric is ambiguous and "approved"
means little. Saved runs live on one machine, so `prepare` writes a self-contained packet (the same
evidence a reviewer sees in the Review tab) plus one blank rating file per reviewer. `score`
reports raw agreement and Cohen's kappa, and lists every disagreement to discuss.

    df scripts/interrater.py prepare            # picks unreviewed runs, writes data/eval/interrater/
    df scripts/interrater.py score data/eval/interrater/ratings-a.txt data/eval/interrater/ratings-b.txt

The ratings use A / R (approve / reject), not `review apply` lines, so a rating is never recorded
as a decision by accident.
"""

import argparse
import random
import sys
from collections import Counter
from pathlib import Path

import yaml
from agent_metrics import CURRENT_PROMPTS, SPLIT_SINCE, load_events, split_of

from detectforge.eval.export import zero_shot
from detectforge.review import list_runs, load_run

RUBRIC = """\
Rubric (the same one used for the test-split review):
- Hardened rule: approve if it passed the quality checks and adds no false alarm.
- Written rule: approve if it passed the quality checks, raises no false alarm on unseen legitimate
  commands, and catches at least 80% of unseen variations; or, with no unseen variations to measure,
  if its logic is tightly scoped on reading.
- Any rule: reject if it would fire on everyday legitimate commands you can think of, even when they
  are not in the test data.
- A rule that did not pass the quality checks can still be approved if you judge the failing check
  wrong for this rule; say why."""


def pick(runs_dir: Path, data_dir: Path, n: int, seed: int) -> list:
    """Unreviewed dev runs on the current split: about 4 in 5 that passed the checks, the rest not."""
    selection = yaml.safe_load((data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))["rules"]
    pool = []
    for s in list_runs(runs_dir):
        if s.decision or s.prompt_version not in CURRENT_PROMPTS or s.created < SPLIT_SINCE:
            continue
        if split_of(s.technique, selection) != "dev":
            continue
        outcome = load_run(runs_dir, s.trace_id)
        if outcome.run.model_calls and not outcome.run.model_calls[-1].ok:
            continue  # outage: no rule to judge
        pool.append(outcome)
    rng = random.Random(seed)
    passed = sorted((o for o in pool if o.run.status == "passed"), key=lambda o: o.run.trace_id)
    other = sorted((o for o in pool if o.run.status != "passed"), key=lambda o: o.run.trace_id)
    n_other = min(len(other), max(1, n // 5))
    chosen = rng.sample(passed, min(len(passed), n - n_other)) + rng.sample(other, n_other)
    rng.shuffle(chosen)
    return chosen


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.0%}"


def packet_entry(i: int, outcome, events_by_id: dict[str, dict]) -> str:
    run, h, prov = outcome.run, outcome.heldout_evaluation, outcome.provenance
    path = (
        "hardened community rule"
        if run.mode == "harden"
        else (
            "written, zero-shot (no tuning variations)"
            if zero_shot(outcome)
            else "written from tuning variations"
        )
    )
    budget = prov.budgets.get("model_calls") if prov else "?"
    lines = [
        f"## {i}. `{run.trace_id[:8]}` · {run.technique} · {path}",
        "",
        f"- Model-call budget: {budget}; calls used: {len(run.model_calls)}",
        f"- Quality checks: **{'passed' if run.status == 'passed' else 'not passed'}**",
    ]
    lines += [f"  - {reason}" for reason in run.reasons]
    warnings = [c for c in run.gate.checks if not c.blocking and not c.passed]
    shown = " ".join(run.reasons)
    lines += [f"  - warning, {c.name}: {c.detail}" for c in warnings if c.detail not in shown]
    lines.append(
        f"- Tuning variations caught: {_pct(run.tuning_evasion_resistance_before)} → "
        f"{_pct(run.tuning_evasion_resistance_after)}; tuning false alarms: {run.tuning_false_alarms_after}"
    )
    if h:
        per_type = ", ".join(
            f"{t} {d.hits_after}/{d.attacks}" for t, d in h.per_transform.items() if t != "none" and d.attacks
        )
        before, after = _pct(h.evasion_resistance_before), _pct(h.evasion_resistance_after)
        lines.append(
            f"- **Unseen variations caught: {before} → {after}**"
            + (f" ({per_type})" if per_type else " (none to measure)")
        )
        new_fa = h.new_false_alarm_event_ids
        lines.append(f"- **New false alarms on unseen legitimate commands: {len(new_fa)}**")
        lines += [f"  - `{events_by_id.get(e, {}).get('command_line', e)}`" for e in new_fa]
        caught = set(h.after.matched_event_ids)
        missed = [
            e
            for e in events_by_id.values()
            if e["label"] == "attack"
            and e.get("split") == "heldout"
            and e["technique"] == run.technique
            and e["transform"] != "none"
            and e["event_id"] not in caught
        ]
        if missed:
            lines.append(f"- Unseen attack variations it misses ({len(missed)}, up to 4 shown):")
            lines += [f"  - {m['transform']}: `{m['command_line']}`" for m in missed[:4]]
    lines += ["", "```yaml", run.final_rule_yaml.strip() or "(no rule)", "```", ""]
    return "\n".join(lines)


def prepare(args: argparse.Namespace) -> int:
    chosen = pick(args.runs_dir, args.data_dir, args.n, args.seed)
    if not chosen:
        print("no unreviewed dev runs to rate", file=sys.stderr)
        return 1
    events_by_id = {e["event_id"]: e for e in load_events(args.data_dir)}
    args.out.mkdir(parents=True, exist_ok=True)
    head = [
        "# Inter-rater review packet",
        "",
        f"{len(chosen)} agent runs from the dev split that nobody has reviewed. Rate each one on your own,"
        " without discussing, in your ratings file (A = approve, R = reject, then a short reason).",
        "",
        RUBRIC,
        "",
        "Unseen variations and legitimate commands are held out from the agent; you see them, it never did.",
        "",
    ]
    body = [packet_entry(i, o, events_by_id) for i, o in enumerate(chosen, 1)]
    (args.out / "packet.md").write_text("\n".join(head + body), encoding="utf-8")
    for who in ("a", "b"):
        rating = [
            f"# Reviewer {who.upper()}: rate each run on your own. Replace ? with A (approve) or R (reject),",
            "# then add a short reason. Read the evidence in packet.md (same order).",
            "",
        ] + [f"{i:2}. {o.run.trace_id[:8]}  ?  " for i, o in enumerate(chosen, 1)]
        (args.out / f"ratings-{who}.txt").write_text("\n".join(rating) + "\n", encoding="utf-8")
    print(f"wrote {args.out / 'packet.md'} and ratings-a.txt, ratings-b.txt ({len(chosen)} runs)")
    return 0


def parse_ratings(text: str) -> dict[str, tuple[str, str]]:
    """'NN. <trace id>  A|R  reason' lines -> {trace id: (A|R, reason)}.

    Blank lines, comments and unrated (?) lines are skipped.
    """
    out = {}
    for line in text.splitlines():
        parts = line.split(None, 3)
        if not parts or line.lstrip().startswith("#") or len(parts) < 3:
            continue
        trace, verdict = parts[1], parts[2].upper()
        if verdict not in ("A", "R"):
            continue
        out[trace] = (verdict, parts[3].strip() if len(parts) > 3 else "")
    return out


def cohen_kappa(a: list[str], b: list[str]) -> float | None:
    """Agreement beyond chance for two raters: 1 = perfect, 0 = what chance alone would give."""
    n = len(a)
    if n == 0:
        return None
    observed = sum(x == y for x, y in zip(a, b, strict=True)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(a) | set(b)) / n**2
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


def score(args: argparse.Namespace) -> int:
    ra = parse_ratings(args.a.read_text(encoding="utf-8"))
    rb = parse_ratings(args.b.read_text(encoding="utf-8"))
    both = sorted(set(ra) & set(rb))
    missing = sorted(set(ra) ^ set(rb))
    if not both:
        print("no run rated by both reviewers", file=sys.stderr)
        return 1
    a, b = [ra[t][0] for t in both], [rb[t][0] for t in both]
    agree = sum(x == y for x, y in zip(a, b, strict=True))
    kappa = cohen_kappa(a, b)
    print(
        f"runs rated by both: {len(both)}"
        + (f" (rated by one only: {', '.join(missing)})" if missing else "")
    )
    print(f"raw agreement: {agree}/{len(both)} ({agree / len(both):.0%})")
    print(f"Cohen's kappa: {kappa:.2f}  (above 0.8 almost perfect, 0.6-0.8 substantial, 0.4-0.6 moderate)")
    print(f"approve rate: A {a.count('A')}/{len(a)}, B {b.count('A')}/{len(b)}")
    disagreements = [t for t in both if ra[t][0] != rb[t][0]]
    if disagreements:
        print("\ndisagreements (discuss these; each one points at an ambiguity in the rubric):")
        for t in disagreements:
            print(f"  {t}  A: {ra[t][0]} {ra[t][1]}\n  {'':8}  B: {rb[t][0]} {rb[t][1]}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("prepare", help="pick runs and write the packet and blank rating files")
    pp.add_argument("--n", type=int, default=20)
    pp.add_argument("--seed", type=int, default=798)
    pp.add_argument("--runs-dir", type=Path, default=Path("data/runs"))
    pp.add_argument("--data-dir", type=Path, default=Path("data"))
    pp.add_argument("--out", type=Path, default=Path("data/eval/interrater"))
    ps = sub.add_parser("score", help="agreement and Cohen's kappa for two rating files")
    ps.add_argument("a", type=Path)
    ps.add_argument("b", type=Path)
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    return prepare(args) if args.cmd == "prepare" else score(args)


if __name__ == "__main__":
    sys.exit(main())
