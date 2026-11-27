"""Continuous validation: re-check our rules against the newest SigmaHQ release.

DetectForge evaluates a pinned SigmaHQ release, so every number is reproducible. Upstream keeps
changing: a rule's logic is edited, a rule is removed, a new release fixes (or breaks) an evasion.
This script, run nightly in CI, finds the latest release, re-scores the same selected rules (by id) on
the same attack library with the same scorer, and compares with the committed Arm 1 results:

- rules whose detection logic changed upstream;
- rules that disappeared from the release;
- rules whose evasion resistance went down (a regression: exit code 1, so the scheduled job alerts)
  or up.

It changes nothing: the pinned release and the committed results stay as they are; a person decides
whether to move to the new release. The new release is downloaded over HTTPS from GitHub but, unlike
the pinned one, has no known checksum; it is only parsed as YAML by the same safe index builder, never
executed. Lives outside the package, so the code fingerprint in each run's setup key is unchanged.

    df scripts/revalidate_latest.py                       # latest release from GitHub
    df scripts/revalidate_latest.py --zip path/to.zip --release r2026-07-01   # a local zip
"""

import argparse
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

import yaml

from detectforge.eval.arms import ArmResult, run_community_arm
from detectforge.events import load_events
from detectforge.reference import sigmahq
from detectforge.reference.index import ReferenceIndex

LATEST_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"


def latest_release() -> tuple[str, str]:
    """(tag, download URL of the all-rules zip) of SigmaHQ's latest release."""
    request = urllib.request.Request(LATEST_API, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    asset = next(a for a in release["assets"] if a["name"] == sigmahq.RELEASE_ASSET)
    return release["tag_name"], asset["browser_download_url"]


def download(url: str, dest: Path) -> Path:
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(sigmahq.MAX_ZIP_BYTES + 1)
    if len(data) > sigmahq.MAX_ZIP_BYTES:
        raise SystemExit(f"release exceeds {sigmahq.MAX_ZIP_BYTES} bytes; not processed")
    dest.write_bytes(data)
    return dest


def _logic(rule_yaml: str) -> str:
    """The detection logic only (metadata edits like 'modified:' dates don't count as a change)."""
    try:
        return json.dumps((yaml.safe_load(rule_yaml) or {}).get("detection"), sort_keys=True, default=str)
    except yaml.YAMLError:
        return rule_yaml


def compare(
    selection: dict, pinned: ReferenceIndex, new: ReferenceIndex, events, committed: ArmResult
) -> dict:
    new_ids = {r.id for r in new.rules}
    pinned_by_id = {r.id: r for r in pinned.rules}
    new_by_id = {r.id: r for r in new.rules}
    kept = [r for r in selection["rules"] if r["id"] in new_ids]
    removed = [r for r in selection["rules"] if r["id"] not in new_ids]
    changed_logic = [
        r
        for r in kept
        if r["id"] in pinned_by_id
        and _logic(pinned_by_id[r["id"]].rule_yaml) != _logic(new_by_id[r["id"]].rule_yaml)
    ]
    rescored = run_community_arm({**selection, "rules": kept}, new, events)
    before = {r.rule_id: r.evasion_resistance for r in committed.rules}
    worse, better = [], []
    for r in rescored.rules:
        old, now = before.get(r.rule_id), r.evasion_resistance
        if old is None or now is None or abs(old - now) < 1e-9:
            continue
        (worse if now < old else better).append((r.rule_id, r.title, old, now))
    return {
        "removed": removed,
        "changed_logic": changed_logic,
        "worse": worse,
        "better": better,
        "kept": len(kept),
    }


def report(tag: str, pinned_tag: str, result: dict) -> str:
    lines = [f"## SigmaHQ re-validation: {tag} (pinned: {pinned_tag})", ""]
    lines.append(f"- Rules re-scored: {result['kept']}; removed upstream: {len(result['removed'])}")
    lines.append(f"- Detection logic changed upstream: {len(result['changed_logic'])}")
    for r in result["changed_logic"]:
        lines.append(f"  - {r['technique']} · {r['title']}")
    for r in result["removed"]:
        lines.append(f"- Removed: {r['technique']} · {r['title']}")
    for label, items in (
        ("Evasion resistance went DOWN", result["worse"]),
        ("Evasion resistance went up", result["better"]),
    ):
        if items:
            lines.append(f"- {label}:")
            lines += [f"  - {title}: {old:.0%} → {now:.0%}" for _, title, old, now in items]
    if not (result["removed"] or result["changed_logic"] or result["worse"] or result["better"]):
        lines.append("- No change: every selected rule scores as in the committed results.")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--zip", type=Path, help="use this release zip instead of downloading the latest")
    p.add_argument("--release", default=None, help="tag of --zip")
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    args = p.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    pinned = ReferenceIndex.load(args.data_dir / "sigmahq")
    with tempfile.TemporaryDirectory() as tmp:
        if args.zip:
            tag, zip_path = args.release or "local", args.zip
        else:
            tag, url = latest_release()
            if tag == pinned.release:
                print(f"SigmaHQ latest release is the pinned one ({tag}); nothing to re-check.")
                return 0
            zip_path = download(url, Path(tmp) / sigmahq.RELEASE_ASSET)
        sigmahq.build_index(zip_path, Path(tmp) / "index", release=tag)
        new = ReferenceIndex.load(Path(tmp) / "index")
    selection = yaml.safe_load((args.data_dir / "eval" / "selection.yml").read_text(encoding="utf-8"))
    events = [e for path in sorted((args.data_dir / "eval").glob("*.jsonl")) for e in load_events(path)]
    committed = ArmResult.model_validate_json(
        (args.data_dir / "eval" / "results" / "arm1_community.json").read_text(encoding="utf-8")
    )
    result = compare(selection, pinned, new, events, committed)
    text = report(tag, pinned.release, result)
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)
    return 1 if result["worse"] or result["removed"] else 0


if __name__ == "__main__":
    sys.exit(main())
