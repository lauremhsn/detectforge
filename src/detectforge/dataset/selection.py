"""Build the evaluation rule set: each picked SigmaHQ rule with the Atomic Red Team commands it detects.

Input is a config listing rule IDs, their primary technique, and the dev techniques. Every rule must
fire on at least one unmutated base attack, and dev and test rules must share no ATT&CK technique
family, so tuning on dev rules cannot leak into test results.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from detectforge.dataset.atomic import ART_COMMIT, load_tests, windows_commands
from detectforge.harness import run
from detectforge.reference.index import ReferenceIndex, technique_family
from detectforge.schemas import TECHNIQUE_PATTERN, Event


class PickedRule(BaseModel):
    id: str
    technique: str = Field(pattern=TECHNIQUE_PATTERN)


class SelectionConfig(BaseModel):
    atomic_red_team_commit: str = ART_COMMIT
    dev_techniques: list[str]
    rules: list[PickedRule]


class SelectedRule(BaseModel):
    id: str
    title: str
    path: str
    status: str
    level: str
    technique: str
    attack_tags: list[str]
    split: str
    base_attacks: list[str]


class BaseAttack(BaseModel):
    event_id: str
    technique: str
    art_test: str
    image: str
    command_line: str
    parent_image: str

    def to_event(self) -> Event:
        return Event(
            event_id=self.event_id,
            image=self.image,
            command_line=self.command_line,
            parent_image=self.parent_image,
            original_file_name=self.image.split("\\")[-1].lower(),
            label="attack",
            technique=self.technique,
            transform="none",
            base_id=self.event_id,
            split="tune",
        )


class Selection(BaseModel):
    sigmahq_release: str
    atomic_red_team_commit: str
    dev_techniques: list[str]
    rules: list[SelectedRule]
    base_attacks: list[BaseAttack]


class SelectionError(ValueError):
    """The config produces an unusable rule set."""


def load_config(path: Path) -> SelectionConfig:
    return SelectionConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def build_selection(config: SelectionConfig, index: ReferenceIndex, art_cache: Path) -> Selection:
    by_id = {r.id: r for r in index.rules}
    missing = [p.id for p in config.rules if p.id not in by_id]
    if missing:
        raise SelectionError(f"rule IDs not in SigmaHQ {index.release}: {missing}")

    dev = set(config.dev_techniques)
    commands = {}
    for tag in sorted({t for p in config.rules for t in by_id[p.id].techniques}):
        doc = load_tests(tag, art_cache, config.atomic_red_team_commit)
        commands[tag] = windows_commands(doc) if doc else []

    attacks: dict[tuple[str, str], BaseAttack] = {}
    selected = []
    for pick in config.rules:
        rule = by_id[pick.id]
        fired = []
        for cmd in (c for tag in rule.techniques for c in commands[tag]):
            key = (pick.technique, cmd.command_line)
            attack = attacks.get(key) or BaseAttack(
                event_id=f"{pick.technique}-b{sum(k[0] == pick.technique for k in attacks) + 1:02d}",
                technique=pick.technique,
                art_test=cmd.test_name,
                image=cmd.image,
                command_line=cmd.command_line,
                parent_image=cmd.parent_image,
            )
            if attack.event_id not in fired and run(rule.rule_yaml, [attack.to_event()]).hits:
                attacks[key] = attack
                fired.append(attack.event_id)
        if not fired:
            raise SelectionError(f"{rule.title} ({rule.id}) fires on no base attack")
        selected.append(
            SelectedRule(
                id=rule.id,
                title=rule.title,
                path=rule.path,
                status=rule.status,
                level=rule.level,
                technique=pick.technique,
                attack_tags=rule.techniques,
                split="dev" if pick.technique in dev else "test",
                base_attacks=fired,
            )
        )

    families = {
        s: {technique_family(t) for r in selected if r.split == s for t in r.attack_tags}
        for s in ("dev", "test")
    }
    if shared := families["dev"] & families["test"]:
        raise SelectionError(f"dev and test rules share technique families: {sorted(shared)}")

    return Selection(
        sigmahq_release=index.release,
        atomic_red_team_commit=config.atomic_red_team_commit,
        dev_techniques=sorted(dev),
        rules=selected,
        base_attacks=list(attacks.values()),
    )


def write_selection(selection: Selection, manifest: Path, events: Path) -> None:
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        yaml.safe_dump(selection.model_dump(), sort_keys=False, width=200, allow_unicode=True),
        encoding="utf-8",
    )
    with open(events, "w", encoding="utf-8", newline="\n") as f:
        for attack in selection.base_attacks:
            f.write(attack.to_event().model_dump_json(exclude_none=True) + "\n")
