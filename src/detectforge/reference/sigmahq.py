"""Fetch a pinned SigmaHQ release and build the reference rule index from it.

The release zip is verified against a pinned SHA-256 and read in memory (never extracted),
so a tampered or malformed archive cannot write files outside the index directory.
"""

import hashlib
import json
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

import yaml

from detectforge.harness.matcher import compile_rule, rule_fields
from detectforge.reference.index import INDEX_FILE, META_FILE, ReferenceRule, techniques_from_tags
from detectforge.rules.parse import SCOPE_CATEGORY, SCOPE_PRODUCT, RuleError, load_rule
from detectforge.schemas import SIGMA_FIELD_MAP

# Pinned so experiments are reproducible and the memorization probe compares against a fixed rule set.
RELEASE_TAG = "r2026-07-01"
RELEASE_ASSET = "sigma_all_rules.zip"
RELEASE_SHA256 = "5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085"
RELEASE_URL = f"https://github.com/SigmaHQ/sigma/releases/download/{RELEASE_TAG}/{RELEASE_ASSET}"

MAX_ZIP_BYTES = 50 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024
EXCLUDED_STATUSES = {"deprecated", "unsupported"}


class ReleaseIntegrityError(ValueError):
    """The downloaded release does not match the pinned checksum or limits."""


def download_release(dest: Path, url: str = RELEASE_URL, timeout_s: float = 60.0) -> Path:
    """Download the pinned release zip to dest and verify its checksum."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=timeout_s) as response:
        data = response.read(MAX_ZIP_BYTES + 1)
    if len(data) > MAX_ZIP_BYTES:
        raise ReleaseIntegrityError(f"release exceeds {MAX_ZIP_BYTES} bytes")
    verify_sha256(data, RELEASE_SHA256)
    dest.write_bytes(data)
    return dest


def verify_sha256(data: bytes, expected: str) -> None:
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ReleaseIntegrityError(f"sha256 mismatch: expected {expected}, got {actual}")


def build_index(zip_path: Path, out_dir: Path, release: str = RELEASE_TAG) -> dict:
    """Index every Windows process-creation rule in the zip. Returns the index metadata."""
    rules: list[ReferenceRule] = []
    skipped: Counter[str] = Counter()
    with zipfile.ZipFile(zip_path) as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.is_dir() or not info.filename.endswith((".yml", ".yaml")):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                skipped["too_large"] += 1
                continue
            rule, reason = _index_rule(info.filename, zf.read(info).decode("utf-8", errors="replace"))
            if rule:
                rules.append(rule)
            elif reason:
                skipped[reason] += 1

    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / INDEX_FILE, "w", encoding="utf-8", newline="\n") as f:
        for rule in rules:
            f.write(rule.model_dump_json() + "\n")
    meta = {
        "release": release,
        "rules_indexed": len(rules),
        "evaluable": sum(r.evaluable for r in rules),
        "skipped": dict(sorted(skipped.items())),
    }
    (out_dir / META_FILE).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def _index_rule(path: str, text: str) -> tuple[ReferenceRule | None, str | None]:
    """Return (rule, None), or (None, skip reason); reason None means silently out of scope."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None, "invalid_yaml"
    if not isinstance(doc, dict) or not isinstance(doc.get("logsource"), dict):
        return None, None  # correlation rules, filters, and other non-detection documents
    logsource = doc["logsource"]
    if logsource.get("category") != SCOPE_CATEGORY or logsource.get("product") != SCOPE_PRODUCT:
        return None, None
    if doc.get("status") in EXCLUDED_STATUSES:
        return None, "excluded_status"
    try:
        sigma_rule = load_rule(text)
    except RuleError:
        return None, "invalid_sigma"

    harness_error = None
    try:
        compile_rule(sigma_rule)
        fields = rule_fields(sigma_rule)
    except RuleError as e:
        harness_error, fields = str(e), set()

    return (
        ReferenceRule(
            id=str(sigma_rule.id or ""),
            title=sigma_rule.title,
            path=path,
            status=str(doc.get("status") or ""),
            level=str(doc.get("level") or ""),
            description=str(doc.get("description") or ""),
            techniques=techniques_from_tags(doc.get("tags") or []),
            falsepositives=[str(fp) for fp in doc.get("falsepositives") or []],
            fields=sorted(fields),
            unmapped_fields=sorted(fields - SIGMA_FIELD_MAP.keys()),
            evaluable=harness_error is None,
            harness_error=harness_error,
            detection_text=yaml.safe_dump(doc.get("detection"), sort_keys=False),
            rule_yaml=text,
        ),
        None,
    )
