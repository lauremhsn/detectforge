"""Generate behaviour-preserving command-line mutations of base attacks, per the Uetz taxonomy.

Each transform is driven by what ArgFuscator reports the binary tolerates (see argfuscator.py), applied
deterministically so the mutation set is reproducible. Mutations are not run here: a sample is confirmed
in the VM (behaviour check). insertion/substitution/omission are tuning; reordering/recoding are held out.
"""

import base64
import ipaddress
import re
from collections.abc import Iterator

from detectforge.dataset.argfuscator import SAFE_INVISIBLES, Capability
from detectforge.schemas import Event, Transform

SPLIT_OF: dict[Transform, str] = {
    "insertion": "tune",
    "substitution": "tune",
    "omission": "tune",
    "reordering": "heldout",
    "recoding": "heldout",
}
MAX_PER_TRANSFORM = 4
_OPTION_CHARS = "/-"
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_FLAG_PAIR = re.compile(r"""(?:^|\s)([/-][^\s"]+)(?:[ =]("[^"]*"|[^\s/-][^\s]*))?""")


def _tokens(command: str) -> list[str]:
    # A token is a run of quoted segments and bare chars, so /category:"Account Logon" stays one token.
    return re.findall(r'(?:"[^"]*"|[^\s"]+)+', command)


def _verb_index(tokens: list[str]) -> int:
    """Index of a true subcommand verb (a non-option token immediately after the image), else 0.

    `reg export ...` and `wmic process ...` have one; `schtasks /create ...` does not (its first
    token after the image is an option flag, so there is no verb to protect or mutate here).
    """
    return 1 if len(tokens) > 1 and not tokens[1].startswith(("/", "-")) else 0


def _insertion(command: str, cap: Capability) -> Iterator[str]:
    if cap.quote_insertion:
        seen = 0
        for flag in re.findall(r"(?:^|\s)([/-])([A-Za-z][\w-]*)", command):
            opt, name = flag
            variant = command.replace(f"{opt}{name}", f'{opt}"{name}"', 1)
            if variant != command:
                yield variant
                seen += 1
                if seen >= 2:
                    break
    if cap.char_insertion:
        tokens = _tokens(command)
        idx = _verb_index(tokens)
        if idx and len(tokens[idx]) >= 2:
            glyph = SAFE_INVISIBLES[0]
            mutated = tokens[idx][0] + glyph + tokens[idx][1:]
            yield command.replace(tokens[idx], mutated, 1)


def _substitution(command: str, cap: Capability) -> Iterator[str]:
    used = set(re.findall(r"(?:^|\s)([/-])[A-Za-z]", command))
    # An ASCII alt helps only if it is not the command's current option char; a Unicode dash always helps.
    for alt in cap.option_chars:
        if alt not in _OPTION_CHARS or alt not in used:
            yield re.sub(r"(^|\s)[/-]([A-Za-z])", rf"\1{alt}\2", command)
    if cap.homoglyphs:
        tokens = _tokens(command)
        idx = _verb_index(tokens)
        if idx:
            sub = "".join(cap.homoglyphs.get(ch.lower(), ch) for ch in tokens[idx])
            if sub != tokens[idx]:
                yield command.replace(tokens[idx], sub, 1)


def _omission(command: str, cap: Capability) -> Iterator[str]:
    if ".exe" in command.lower():
        yield re.sub(r"\.exe\b", "", command, count=1, flags=re.IGNORECASE)
    for long, short in cap.shorthands.items():
        pattern = re.compile(rf"([/-]){long}\b", re.IGNORECASE)
        if pattern.search(command):
            yield pattern.sub(rf"\1{short}", command, count=1)
            break


def _reordering(command: str, cap: Capability) -> Iterator[str]:
    """Swap the first two top-level flag units (a `/flag` with its optional value). Skipped when a
    positional argument follows the subcommand, since its position carries meaning
    (e.g. `reg export HKLM\\sam file`). Operates on tokens, so content inside quotes is never touched."""
    tokens = _tokens(command)
    start = (_verb_index(tokens) or 0) + 1
    units: list[list[str]] = []
    positional = False
    i = start
    while i < len(tokens):
        if tokens[i].startswith(("/", "-")):
            if i + 1 < len(tokens) and not tokens[i + 1].startswith(("/", "-")):
                units.append(tokens[i : i + 2])
                i += 2
            else:
                units.append([tokens[i]])
                i += 1
        else:
            positional = True
            break
    # Keep the first flag fixed (it is often the verb, e.g. auditpol /set, schtasks /create) and
    # swap the next two, so the mutation reorders real option flags, never the command's operation.
    if positional or len(units) < 3:
        return
    reordered = tokens[:start] + units[0] + units[2] + units[1] + [t for u in units[3:] for t in u]
    swapped = " ".join(reordered)
    if swapped != command:
        yield swapped


def _recoding(command: str, cap: Capability) -> Iterator[str]:
    if cap.ip_to_hex:
        match = _IPV4.search(command)
        if match:
            packed = int(ipaddress.IPv4Address(match.group(1)))
            yield command[: match.start(1)] + str(packed) + command[match.end(1) :]
            yield command[: match.start(1)] + f"0x{packed:08x}" + command[match.end(1) :]
    if cap.binary == "powershell" and "-e" not in command.lower():
        # -Command "X", or a bare quoted script as the first argument, both become -EncodedCommand <base64>.
        m = re.search(r'(?:-c|-command)\s+"([^"]*)"', command, re.IGNORECASE) or re.search(
            r'(?i)powershell(?:\.exe)?"?\s+"([^"]*)"', command
        )
        if m:
            encoded = base64.b64encode(m.group(1).encode("utf-16-le")).decode("ascii")
            yield command[: m.start(1) - 1] + f"-EncodedCommand {encoded}" + command[m.end(1) + 1 :]


_TRANSFORMS = {
    "insertion": _insertion,
    "substitution": _substitution,
    "omission": _omission,
    "reordering": _reordering,
    "recoding": _recoding,
}


def mutate_command(command: str, cap: Capability) -> dict[Transform, list[str]]:
    """Deterministic, de-duplicated mutations of one command line, grouped by transform type."""
    out: dict[Transform, list[str]] = {}
    for name, fn in _TRANSFORMS.items():
        seen: list[str] = []
        for variant in fn(command, cap):
            if variant != command and variant not in seen:
                seen.append(variant)
            if len(seen) >= MAX_PER_TRANSFORM:
                break
        if seen:
            out[name] = seen  # type: ignore[index]
    return out


def mutate_event(base: Event, cap: Capability) -> list[Event]:
    """Mutated events derived from one base attack, numbered within each transform type."""
    events = []
    for transform, variants in mutate_command(base.command_line, cap).items():
        for i, command in enumerate(variants, 1):
            events.append(
                base.model_copy(
                    update={
                        "event_id": f"{base.event_id}-{transform[:3]}{i}",
                        "command_line": command,
                        "transform": transform,
                        "base_id": base.event_id,
                        "split": SPLIT_OF[transform],
                    }
                )
            )
    return events


def build_mutations(base_events: list[Event], cache_dir) -> list[Event]:
    """All mutations for a list of base attacks. Binaries ArgFuscator does not model get only the
    transforms that need no capability (dropping `.exe`)."""
    from detectforge.dataset.argfuscator import load_capability

    out = []
    for base in base_events:
        binary = base.image.split("\\")[-1]
        cap = load_capability(binary, cache_dir) or Capability(binary=binary.lower().removesuffix(".exe"))
        out += mutate_event(base, cap)
    return out
