"""Benign look-alike events ("hard negatives") for measuring rule precision.

Each entry is a legit use of the same binary an attack abuses. Class A differs from the attack in a way
you can see on the command line, so a precise rule shouldn't fire. Class B can't be told from the attack
by command line alone, so it's reported on its own and never counts as a rule being too broad. All of
these are benign events. Most are held out for measuring precision; a few per technique are marked
split: tune so the agent sees "benign exists" during hardening (disjoint from the held-out ones).
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from detectforge.dataset.atomic import CMD, POWERSHELL, SYSTEM32
from detectforge.schemas import Event


class Negative(BaseModel):
    cmd: str
    hn_class: str = Field(alias="class", pattern="^[AB]$")
    note: str
    split: str = Field(default="heldout", pattern="^(tune|heldout)$")


class HardNegatives(BaseModel):
    negatives: dict[str, list[Negative]]


def _image_and_parent(command: str) -> tuple[str, str]:
    command = command.strip()
    # the leading token may be a quoted path that contains spaces
    token = command[1 : command.index('"', 1)] if command.startswith('"') else command.split()[0]
    name = token.split("\\")[-1].lower()
    name = name if name.endswith(".exe") else name + ".exe"
    if "\\" in token and token.lower().endswith(".exe"):
        image = token
    elif name == "powershell.exe":
        image = POWERSHELL
    else:
        image = SYSTEM32 + name
    parent = POWERSHELL if name == "powershell.exe" else CMD
    return image, parent


def load(path: Path) -> HardNegatives:
    return HardNegatives.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def build_events(config: HardNegatives) -> tuple[list[Event], list[Event]]:
    """Give back (class A events, class B events). Event ids are <technique>-n{a,b}{n}."""
    class_a: list[Event] = []
    class_b: list[Event] = []
    for technique, entries in config.negatives.items():
        counts = {"A": 0, "B": 0}
        for entry in entries:
            counts[entry.hn_class] += 1
            image, parent = _image_and_parent(entry.cmd)
            eid = f"{technique}-n{entry.hn_class.lower()}{counts[entry.hn_class]}"
            event = Event(
                event_id=eid,
                image=image,
                command_line=entry.cmd,
                parent_image=parent,
                original_file_name=image.split("\\")[-1].lower(),
                label="benign",
                technique=technique,
                transform="none",
                base_id=eid,
                split=entry.split,
            )
            (class_a if entry.hn_class == "A" else class_b).append(event)
    return class_a, class_b
