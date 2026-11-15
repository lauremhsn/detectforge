"""Plot Arm 1 (community rules as-is) evasion resistance by transform.

Reads data/eval/results/arm1_community.json (written by `detectforge eval community`) and writes
analysis/arm1_evasion_resistance.png. Figures are generated from committed results, never by hand.
"""

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt

RESULTS = Path("data/eval/results/arm1_community.json")
OUT = Path("analysis/arm1_evasion_resistance.png")
LABELS = {
    "insertion": "Insertion",
    "substitution": "Substitution",
    "omission": "Omission",
    "reordering": "Reordering",
    "recoding": "Recoding",
}


def main() -> int:
    if not RESULTS.exists():
        print(f"missing {RESULTS}; run `detectforge eval community` first", file=sys.stderr)
        return 1
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    by_t = data["resistance_by_transform"]
    transforms = [t for t in LABELS if by_t.get(t) is not None]
    values = [by_t[t] for t in transforms]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.barh(
        [LABELS[t] for t in transforms],
        values,
        color=["#c0392b" if v < 0.8 else "#2e86de" for v in values],
    )
    overall = data["overall_evasion_resistance"]
    ax.axvline(overall, color="#555", linestyle="--", linewidth=1)
    ax.text(overall, -0.7, f"overall {overall:.0%}", ha="center", fontsize=8, color="#555")
    ax.set_xlim(0, 1)
    ax.set_xlabel("Evasion resistance (fraction of mutations still detected)")
    ax.set_title(f"Community SigmaHQ rules as-is ({data['rules']} rules)")
    ax.invert_yaxis()
    for bar, v in zip(bars, values, strict=True):
        ax.text(v + 0.01, bar.get_y() + bar.get_height() / 2, f"{v:.0%}", va="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT, dpi=150)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
