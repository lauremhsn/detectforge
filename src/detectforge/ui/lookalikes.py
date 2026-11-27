"""Extra look-alikes: everyday legitimate commands that aren't in the dataset.

A rule can show "0 false alarms" simply because the dataset lacks the command it would fire on.
Reviewing agent rules found such commands (e.g. `reg query HKLM\\SYSTEM\\...`), so the Review page
replays every proposal against them too. They live in their own file, never in the main event files
(whose hash is part of each run's setup key), and are reported apart from the evaluation.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError

from detectforge.harness import run
from detectforge.schemas import Event


class Lookalike(BaseModel):
    id: str
    technique: str
    binary: str
    why: str
    cmd: str

    def event(self) -> Event:
        return Event(
            event_id=self.id,
            image=f"C:\\Windows\\System32\\{self.binary}",
            command_line=self.cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            original_file_name=self.binary,
            label="benign",
            technique=self.technique,
            transform="none",
            base_id=self.id,
            split="heldout",
        )


def load_lookalikes(data_dir: Path) -> list[Lookalike]:
    path = data_dir / "eval" / "extra_lookalikes.yml"
    try:
        items = yaml.safe_load(path.read_text(encoding="utf-8"))["lookalikes"]
        return [Lookalike.model_validate(i) for i in items]
    except (OSError, KeyError, TypeError, yaml.YAMLError, ValidationError):
        return []


def firing_lookalikes(rule_yaml: str, lookalikes: list[Lookalike]) -> list[Lookalike]:
    """The look-alikes this rule fires on (none if the rule can't be evaluated)."""
    if not rule_yaml or not lookalikes:
        return []
    card = run(rule_yaml, [x.event() for x in lookalikes])
    hits = set(card.matched_event_ids) if card.valid else set()
    return [x for x in lookalikes if x.id in hits]
