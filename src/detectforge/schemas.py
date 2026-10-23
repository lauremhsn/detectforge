"""Frozen cross-team interfaces (CLAUDE.md section 7, docs/interfaces.md).

Any change here needs agreement from both Marwa and Laure.
"""

from typing import Literal, Self, get_args

from pydantic import BaseModel, ConfigDict, Field, model_validator

Label = Literal["attack", "benign"]
Transform = Literal["none", "insertion", "substitution", "omission", "reordering", "recoding"]
Split = Literal["tune", "heldout"]
RuleSource = Literal["community", "adapted", "written"]
RuleStatus = Literal["proposed", "approved", "rejected"]

TRANSFORMS: tuple[Transform, ...] = get_args(Transform)
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"

# Sigma field name -> Event attribute. Sigma fields not listed here are absent from every event.
SIGMA_FIELD_MAP: dict[str, str] = {
    "Image": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image",
}


class Event(BaseModel):
    """One Sysmon Event ID 1 (process creation) record, stored as one JSON line."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1)
    image: str
    command_line: str
    parent_image: str
    label: Label
    technique: str = Field(pattern=TECHNIQUE_PATTERN)
    transform: Transform
    base_id: str = Field(min_length=1, description="Event this was mutated from; itself if unmutated.")
    split: Split

    @model_validator(mode="after")
    def _base_id_consistent(self) -> Self:
        if self.transform == "none" and self.base_id != self.event_id:
            raise ValueError("unmutated events (transform 'none') must have base_id == event_id")
        if self.transform != "none" and self.base_id == self.event_id:
            raise ValueError("mutated events must reference a different base_id")
        return self


class TransformBreakdown(BaseModel):
    """Counts for the events sharing one transform type."""

    attacks: int = 0
    hits: int = 0
    misses: int = 0
    benign: int = 0
    false_alarms: int = 0


class Scorecard(BaseModel):
    """Result of replaying one rule against a list of events.

    hits/misses count attack events; false_alarms counts benign events the rule matched.
    When valid is False the rule could not be evaluated, error says why, and all counts are zero.
    """

    valid: bool
    error: str | None = None
    hits: int = 0
    misses: int = 0
    false_alarms: int = 0
    matched_event_ids: list[str] = Field(default_factory=list)
    per_transform: dict[Transform, TransformBreakdown] = Field(
        default_factory=lambda: {t: TransformBreakdown() for t in TRANSFORMS}
    )


class RuleRecord(BaseModel):
    """A rule moving through the find/adapt/write -> approve pipeline."""

    rule_yaml: str
    source: RuleSource
    technique: str = Field(pattern=TECHNIQUE_PATTERN)
    trace_id: str
    version: int = Field(ge=1)
    status: RuleStatus = "proposed"


class ValidationResult(BaseModel):
    """Output of validate_rule. errors make a rule unusable; warnings are advisory."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
