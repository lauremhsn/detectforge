"""Searchable index of community (SigmaHQ) reference rules.

Rule text comes from an external repository and is untrusted input: callers must pass it to the
model as data, never as instructions.
"""

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from detectforge.schemas import TECHNIQUE_PATTERN

INDEX_FILE = "index.jsonl"
META_FILE = "meta.json"
# Bump when ReferenceRule or the event schema changes; older indexes must be rebuilt.
INDEX_FORMAT = 2
MAX_LIMIT = 20

MatchKind = Literal["technique", "related_technique", "query"]

_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TOKEN = re.compile(r"[a-z0-9_]{2,}")
_STATUS_RANK = {"stable": 0, "test": 1, "experimental": 2}
_CAMPAIGN_DIRS = ("rules-emerging-threats/",)
_LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


class ReferenceRule(BaseModel):
    id: str
    title: str
    path: str
    status: str
    level: str
    description: str
    techniques: list[str]
    falsepositives: list[str]
    fields: list[str]
    unmapped_fields: list[str] = Field(description="Fields the event schema lacks; they never match.")
    evaluable: bool = Field(description="The harness can run this rule.")
    can_fire: bool = Field(description="False if it depends on fields events lack, so it never matches.")
    harness_error: str | None = None
    detection_text: str
    rule_yaml: str

    @property
    def usable(self) -> bool:
        """A candidate for hardening. If no technique match is usable, the write-new-rule fallback runs."""
        return self.evaluable and self.can_fire


class ReferenceHit(BaseModel):
    rule: ReferenceRule
    match: MatchKind
    score: float


def techniques_from_tags(tags: list[str]) -> list[str]:
    """['attack.t1053.005', 'attack.persistence'] -> ['T1053.005']"""
    found = (_TECHNIQUE_TAG.match(str(t)) for t in tags)
    return sorted({m.group(1).upper() for m in found if m})


def technique_family(technique: str) -> str:
    """T1053.005 -> T1053"""
    return technique.split(".")[0]


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text.lower()))


class ReferenceIndex:
    def __init__(self, rules: list[ReferenceRule], release: str = "unknown"):
        self.rules = rules
        self.release = release
        self._title_tokens = [_tokens(r.title) for r in rules]
        self._body_tokens = [
            _tokens(" ".join([r.description, r.detection_text, *r.techniques])) for r in rules
        ]

    @classmethod
    def load(cls, index_dir: Path) -> "ReferenceIndex":
        index_path, meta_path = index_dir / INDEX_FILE, index_dir / META_FILE
        if not index_path.exists() or not meta_path.exists():
            raise FileNotFoundError(f"no reference index at {index_dir}; run `detectforge sigmahq fetch`")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("format") != INDEX_FORMAT:
            raise FileNotFoundError(
                f"reference index at {index_dir} is an old format; "
                "rebuild it with `detectforge sigmahq fetch`"
            )
        with open(index_path, encoding="utf-8") as f:
            rules = [ReferenceRule.model_validate_json(line) for line in f if line.strip()]
        return cls(rules, meta["release"])

    def search(
        self,
        technique: str | None = None,
        query: str | None = None,
        limit: int = 5,
        exclude_technique: str | None = None,
    ) -> list[ReferenceHit]:
        """Find reference rules by ATT&CK technique and/or free-text query.

        technique: exact tag matches rank above parent/sub-technique matches.
        query: ranks by token overlap with title (weighted x2), description, and detection logic;
            with a technique, it only reorders technique matches.
        exclude_technique: drop every rule in that technique's family (e.g. all of T1053.* for
            T1053.005), used by the "written" arm so the agent cannot copy a same-technique rule.
            Rules with no ATT&CK tag are dropped too: some cover the excluded technique untagged
            (e.g. campaign rules that create scheduled tasks), so keeping them would leak.
        """
        if technique is None and not query:
            raise ValueError("give a technique, a query, or both")
        if not 1 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
        for t in (technique, exclude_technique):
            if t is not None and not re.match(TECHNIQUE_PATTERN, t):
                raise ValueError(f"invalid technique id {t!r}")
        excluded_family = technique_family(exclude_technique) if exclude_technique else None
        query_tokens = _tokens(query or "")

        hits = []
        for i, rule in enumerate(self.rules):
            if excluded_family and (
                not rule.techniques or any(technique_family(t) == excluded_family for t in rule.techniques)
            ):
                continue
            text_score = 2 * len(query_tokens & self._title_tokens[i]) + len(
                query_tokens & self._body_tokens[i]
            )
            if technique:
                if technique in rule.techniques:
                    match: MatchKind = "technique"
                    score = 100.0 + text_score
                elif any(technique_family(t) == technique_family(technique) for t in rule.techniques):
                    match, score = "related_technique", 50.0 + text_score
                else:
                    continue
            elif text_score:
                match, score = "query", float(text_score)
            else:
                continue
            hits.append(ReferenceHit(rule=rule, match=match, score=score))

        # Ties: prefer general, focused rules over campaign-specific ones (emerging-threats rules and
        # rules tagged with many techniques are usually IOC bundles for one actor or malware family).
        hits.sort(
            key=lambda h: (
                -h.score,
                not h.rule.usable,
                h.rule.path.startswith(_CAMPAIGN_DIRS),
                len(h.rule.techniques),
                _STATUS_RANK.get(h.rule.status, 9),
                _LEVEL_RANK.get(h.rule.level, 9),
                h.rule.id,
            )
        )
        return hits[:limit]
