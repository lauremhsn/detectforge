"""Stress check: re-score saved rules against legitimate look-alikes that are NOT in the dataset.

The headline false-alarm numbers are measured on a fixed set of look-alikes. A rule can score
"0 false alarms" just because the set lacks the command it would fire on: reviewing the test split
found three rules that fire on everyday `reg query/add/delete` of HKLM\\SYSTEM. This script measures
that gap for every rule, in every arm, with no model calls:
- the community rules (Arm 1);
- the hardened rules (Arm 2);
- the written rules (Arm 3).

It is a post-hoc check, added after the test split was run. It is reported separately and never
changes the frozen results, and the look-alikes are kept out of the main event files, whose hash is
part of every run's setup key.

    df scripts/stress_check.py                                   # test split, frozen budget
    df scripts/stress_check.py --labels data/eval/labelling/labels-a.txt
        counts only look-alikes labelled A (a precise rule must stay silent) as false alarms;
        B (inherently ambiguous) is reported apart, X (malicious) is dropped
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from agent_metrics import CURRENT_PROMPTS, SPLIT_SINCE, split_of
from label_agreement import parse_labels

from detectforge.eval.export import zero_shot
from detectforge.harness import run
from detectforge.reference.index import ReferenceIndex
from detectforge.review import list_runs, load_run
from detectforge.schemas import Event
from detectforge.ui.lookalikes import load_lookalikes


def lookalike_events(data_dir: Path = Path("data")) -> list[Event]:
    """The everyday look-alikes (data/eval/extra_lookalikes.yml) as benign process-creation events.

    The same file the Review page checks every proposal against. The first 7 are the pilot items of
    the labelling sheet (pilot-1..7 are extra-1..7), so their labels apply here.
    """
    return [x.event() for x in load_lookalikes(data_dir)]


def rules_to_check(runs_dir: Path, data_dir: Path, split: str, budget: int) -> list[dict]:
    selection = yaml.safe_load((data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))
    index = ReferenceIndex.load(data_dir / "sigmahq")
    by_id = {r.id: r for r in index.rules}
    rules = []
    for r in selection["rules"]:
        in_split = split == "all" or split_of(r["technique"], selection["rules"]) == split
        if in_split and r["id"] in by_id:
            rules.append({
                "arm": "1 community", "id": r["id"][:8], "technique": r["technique"],
                "title": r["title"], "yaml": by_id[r["id"]].rule_yaml, "decision": "-",
            })  # fmt: skip
    for s in list_runs(runs_dir):
        if s.prompt_version not in CURRENT_PROMPTS or s.created < SPLIT_SINCE:
            continue
        if split != "all" and split_of(s.technique, selection["rules"]) != split:
            continue
        outcome = load_run(runs_dir, s.trace_id)
        r = outcome.run
        if not r.final_rule_yaml.strip() or (r.model_calls and not r.model_calls[-1].ok):
            continue
        if (
            r.mode == "write"
            and outcome.provenance
            and outcome.provenance.budgets.get("model_calls") != budget
        ):
            continue
        arm = (
            "2 hardened"
            if r.mode == "harden"
            else ("3 written, zero-shot" if zero_shot(outcome) else "3 written, with variations")
        )
        rules.append({
            "arm": arm, "id": r.trace_id[:8], "technique": r.technique, "title": "",
            "yaml": r.final_rule_yaml, "decision": s.decision.decision if s.decision else "pending",
            "passed": r.status == "passed",
        })  # fmt: skip
    return rules


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--split", choices=["dev", "test", "all"], default="test")
    p.add_argument("--budget", type=int, default=15, help="write runs with this model-call budget")
    p.add_argument("--labels", type=Path, help="pilot labels (A/B/X) deciding what counts as a false alarm")
    p.add_argument("--runs-dir", type=Path, default=Path("data/runs"))
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    events = lookalike_events(args.data_dir)
    labels = (
        {
            k.replace("pilot-", "extra-"): v[0]
            for k, v in parse_labels(args.labels.read_text(encoding="utf-8")).items()
        }
        if args.labels
        else {}
    )
    if labels:
        events = [e for e in events if labels.get(e.event_id) != "X"]
    counted = {e.event_id for e in events if labels.get(e.event_id, "A") == "A"}  # unlabelled count as A
    ambiguous = {e.event_id for e in events if labels.get(e.event_id) == "B"}

    rules = rules_to_check(args.runs_dir, args.data_dir, args.split, args.budget)
    fires: dict[str, list[dict]] = defaultdict(list)
    by_arm: dict[str, list[dict]] = defaultdict(list)
    for rule in rules:
        card = run(rule["yaml"], events)
        rule["hits"] = set(card.matched_event_ids) if card.valid else set()
        by_arm[rule["arm"]].append(rule)
        for e in rule["hits"]:
            fires[e].append(rule)

    note = "" if labels else " (no labels given: every look-alike counts as a false alarm)"
    print(f"split {args.split}; {len(events)} look-alikes not in the dataset{note}\n")
    print(f"{'arm':28} {'rules':>5}  {'fire on >=1':>11}  {'approved & fire':>15}  ambiguous (B) hits")
    for arm in sorted(by_arm):
        group = by_arm[arm]
        firing = [r for r in group if r["hits"] & counted]
        approved = [r for r in firing if r["decision"] == "approved"]
        b_hits = sum(len(r["hits"] & ambiguous) for r in group)
        print(f"{arm:28} {len(group):>5}  {len(firing):>11}  {len(approved):>15}  {b_hits}")
    print("\nper look-alike: which rules fire")
    for e in events:
        tag = "B" if e.event_id in ambiguous else "A" if labels else "?"
        hit = fires.get(e.event_id, [])
        print(f"  [{tag}] {e.event_id} {e.command_line}")
        for r in hit:
            print(f"        {r['arm']:28} {r['id']} {r['technique']:10} {r['decision']:8} {r['title'][:40]}")
        if not hit:
            print("        (no rule fires)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
