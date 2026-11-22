"""Inter-rater agreement on hard-negative labels (class A vs B), the judgment call in our dataset.

Rule scores are computed by the harness, so there is nothing for two people to disagree on. What
*is* a human judgment is the label of each legitimate look-alike command:
- A: a precise rule should stay silent on it;
- B: the command line alone can't tell it from the attack.

A wrong label moves the false-alarm metric. So we measure whether two people applying the written
rubric agree.

    df scripts/label_agreement.py prepare
        writes data/eval/labelling/: a blind labelling sheet for the 58 existing hard negatives
        (main) and the 7 new look-alikes (pilot), plus a blank file per labeller
    df scripts/label_agreement.py score data/eval/labelling/labels-a.txt --against-dataset
        compares one labeller with the dataset's own labels (written by its author)
    df scripts/label_agreement.py score data/eval/labelling/labels-a.txt data/eval/labelling/labels-b.txt
        compares two labellers (both blind, e.g. on the pilot)

With 2 labellers, a few dozen items and many more A than B labels, kappa swings a lot when one item
changes, and can be low even when agreement is high. So raw agreement is reported next to it.
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

HARD_NEGATIVES = Path("data/eval/hard_negatives.yml")
OUT = Path("data/eval/labelling")

# Pilot: new look-alikes not yet in the dataset (found when reviewing the test split), with the
# technique whose attack they resemble.
PILOT = [
    (
        "T1003.002",
        r"reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager /v PendingFileRenameOperations",
    ),
    ("T1003.002", r"reg query HKLM\SECURITY\Policy"),
    (
        "T1003.002",
        r"reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f",
    ),
    ("T1003.002", r"reg delete HKLM\SYSTEM\CurrentControlSet\Services\OldDriver /f"),
    ("T1547.001", r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OldApp /f'),
    ("T1543.003", r'wmic service where name="OldSvc" delete'),
    ("T1490", r"wbadmin start systemstatebackup -backupTarget:E: -quiet"),
]

RUBRIC = """\
Rubric (decide from the command line and the attack description only):
- A, over-breadth near-miss: the same tool, but a different action or target than the attack (read
  instead of write, a benign key or file instead of a sensitive one, local instead of remote). A rule
  written precisely for the attack would NOT match it; a rule that fires on it is too broad.
- B, inherent ambiguity: the same action on the same kind of target as the attack, run for a
  legitimate reason. No rule on the command line alone could tell them apart; only context could
  (who ran it, the process tree, the destination's reputation).
Ask: "Could I write a rule that catches every version of this attack and still stays silent on this
command?" Yes = A. No = B. If the command is itself malicious, write X and say why."""


def attack_descriptions(text: str) -> dict[str, str]:
    """The '# <rule>   (attack ...)' comment next to each technique key in hard_negatives.yml."""
    return {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"^\s{2}(T\d{4}(?:\.\d{3})?):\s*#\s*(.+)$", text, re.M)
    }


def items() -> list[dict]:
    """Every item to label, in a stable order: main (the dataset, with its author's label), then pilot."""
    text = HARD_NEGATIVES.read_text(encoding="utf-8")
    described = attack_descriptions(text)
    out = []
    for technique, negatives in yaml.safe_load(text)["negatives"].items():
        for k, neg in enumerate(negatives, 1):
            out.append({
                "id": f"{technique}-n{k}", "set": "main", "technique": technique,
                "attack": described.get(technique, ""), "cmd": neg["cmd"], "dataset_label": neg["class"],
            })  # fmt: skip
    for k, (technique, cmd) in enumerate(PILOT, 1):
        out.append({
            "id": f"pilot-{k}", "set": "pilot", "technique": technique,
            "attack": described.get(technique, ""), "cmd": cmd, "dataset_label": None,
        })  # fmt: skip
    return out


def prepare(_: argparse.Namespace) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    all_items = items()
    sheet = [
        "# Hard-negative labelling sheet (blind)",
        "",
        "Label every command on your own, without looking at `hard_negatives.yml` (its class and notes",
        "are the answers) and without discussing. Write A, B or X in your labels file, plus a short reason.",
        "",
        RUBRIC,
        "",
    ]
    for section, title in (
        ("main", "Main set: the dataset's hard negatives"),
        ("pilot", "Pilot: new look-alikes"),
    ):
        sheet += [f"## {title}", ""]
        for it in (i for i in all_items if i["set"] == section):
            sheet += [
                f"**{it['id']}** · {it['technique']} · attack: {it['attack']}",
                "",
                f"    {it['cmd']}",
                "",
            ]
    (OUT / "sheet.md").write_text("\n".join(sheet), encoding="utf-8")
    for who in ("a", "b"):
        lines = [
            f"# Labeller {who.upper()}: replace ? with A, B or X, then a short reason. Items: sheet.md.",
            "# Main set: skip it if you wrote the dataset's labels (they are what it is compared with).",
            "",
        ] + [f"{it['id']}  ?  " for it in all_items]
        (OUT / f"labels-{who}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    n_main = sum(i["set"] == "main" for i in all_items)
    print(
        f"wrote {OUT / 'sheet.md'}, labels-a.txt and labels-b.txt ({n_main} main + {len(PILOT)} pilot items)"
    )
    return 0


def parse_labels(text: str) -> dict[str, tuple[str, str]]:
    """'<id>  A|B|X  reason' lines -> {id: (label, reason)}. Comments and unlabelled (?) lines skipped."""
    out = {}
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2 or line.lstrip().startswith("#") or parts[1].upper() not in ("A", "B", "X"):
            continue
        out[parts[0]] = (parts[1].upper(), parts[2].strip() if len(parts) > 2 else "")
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


def report(name: str, ids: list[str], first: dict, second: dict, who: tuple[str, str]) -> None:
    ids = [i for i in ids if i in first and i in second]
    if not ids:
        return
    a, b = [first[i][0] for i in ids], [second[i][0] for i in ids]
    agree = sum(x == y for x, y in zip(a, b, strict=True))
    kappa = cohen_kappa(a, b)
    print(f"\n== {name}: {len(ids)} items labelled by both")
    print(f"  raw agreement: {agree}/{len(ids)} ({agree / len(ids):.0%})")
    print(
        f"  Cohen's kappa: {kappa:.2f}"
        + ("  (one label only: kappa says nothing here)" if len(set(a + b)) == 1 else "")
    )
    print(f"  labels: {who[0]} {dict(Counter(a))}, {who[1]} {dict(Counter(b))}")
    for i in ids:
        if first[i][0] != second[i][0]:
            (x, why_x), (y, why_y) = first[i], second[i]
            print(f"  disagree {i}: {who[0]} {x} ({why_x}) / {who[1]} {y} ({why_y})")


def score(args: argparse.Namespace) -> int:
    all_items = items()
    first = parse_labels(args.a.read_text(encoding="utf-8"))
    if args.against_dataset:
        second = {i["id"]: (i["dataset_label"], "dataset") for i in all_items if i["dataset_label"]}
        who = ("labeller", "dataset")
    elif args.b:
        second = parse_labels(args.b.read_text(encoding="utf-8"))
        who = ("A", "B")
    else:
        print("give a second labels file or --against-dataset", file=sys.stderr)
        return 2
    for section in ("main", "pilot"):
        report(section, [i["id"] for i in all_items if i["set"] == section], first, second, who)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare", help="write the blind sheet and blank label files")
    ps = sub.add_parser("score", help="raw agreement and Cohen's kappa")
    ps.add_argument("a", type=Path)
    ps.add_argument("b", type=Path, nargs="?")
    ps.add_argument(
        "--against-dataset", action="store_true", help="compare with the labels in hard_negatives.yml"
    )
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    return prepare(args) if args.cmd == "prepare" else score(args)


if __name__ == "__main__":
    sys.exit(main())
