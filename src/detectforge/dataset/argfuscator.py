"""Per-binary command-line obfuscation capabilities from the ArgFuscator project, pinned to one commit.

ArgFuscator (https://github.com/wietze/ArgFuscator.net, GPL-3.0) ships one model per Windows binary
listing the obfuscations that binary is known to tolerate on Windows 11. We read those models as a
capability table only (never vendor the files, to keep this repo MIT) and drive our own deterministic
transforms from them. A binary without a model gets no ArgFuscator-backed transforms.
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ARGFUSCATOR_COMMIT = "aeca415b04f40246232bb3c37798f54664c5c940"
MODEL_URL = "https://raw.githubusercontent.com/wietze/ArgFuscator.net/{commit}/models/{binary}.json"
MAX_MODEL_BYTES = 2 * 1024 * 1024

# Invisible characters ArgFuscator inserts that are safe, well-defined code points (soft hyphen,
# combining grapheme joiner), not the full unassigned-codepoint list. VM verification confirms the rest.
SAFE_INVISIBLES = ("­", "͏")


class ArgfuscatorFetchError(RuntimeError):
    """A model could not be downloaded or is over the size limit."""


@dataclass(frozen=True)
class Capability:
    """What one binary tolerates, distilled from its ArgFuscator model."""

    binary: str
    option_chars: tuple[str, ...] = ()
    quote_insertion: bool = False
    char_insertion: bool = False
    reorder: bool = False
    ip_to_hex: bool = False
    homoglyphs: dict[str, str] = field(default_factory=dict)
    shorthands: dict[str, str] = field(default_factory=dict)

    @property
    def modeled(self) -> bool:
        return True


def _parse_sed(statements: str) -> tuple[dict[str, str], dict[str, str]]:
    """Split ArgFuscator Sed rules into single-char homoglyphs and whole-word shorthands.

    `s/a/<glyph>/i` is a substitution homoglyph; `s/encodedcommand/ec/i` is an omission shorthand.
    Only the first replacement option (before any `|`) is kept, for determinism.
    """
    homoglyphs, shorthands = {}, {}
    for line in statements.splitlines():
        parts = line.strip().split("/")
        if len(parts) < 4 or parts[0] != "s":
            continue
        lhs, rhs = parts[1], parts[2].split("|")[0]
        if not lhs or not rhs:
            continue
        if len(lhs) == 1 and lhs.isascii():
            homoglyphs.setdefault(lhs.lower(), rhs)
        elif lhs.isalpha():
            shorthands.setdefault(lhs.lower(), rhs)
    return homoglyphs, shorthands


def capability_from_model(binary: str, model: dict) -> Capability:
    modifiers: dict = {}
    for profile in model.get("profiles", []):
        modifiers.update(profile.get("parameters", {}).get("modifiers", {}))

    opt = modifiers.get("OptionCharSubstitution", {})
    homoglyphs, shorthands = {}, {}
    if "Sed" in modifiers:
        homoglyphs, shorthands = _parse_sed(modifiers["Sed"].get("SedStatements", ""))

    return Capability(
        binary=binary,
        option_chars=tuple(opt.get("OutputOptionChars", ())),
        quote_insertion="QuoteInsertion" in modifiers,
        char_insertion="CharacterInsertion" in modifiers,
        reorder="ReorderArgs" in modifiers,
        ip_to_hex=bool(modifiers.get("UrlTransformer", {}).get("IpToHex", False)),
        homoglyphs=homoglyphs,
        shorthands=shorthands,
    )


def load_capability(binary: str, cache_dir: Path, commit: str = ARGFUSCATOR_COMMIT) -> Capability | None:
    """Capability for a binary (cached on disk), or None if ArgFuscator has no model for it."""
    binary = binary.lower().removesuffix(".exe")
    path = cache_dir / commit / f"{binary}.json"
    if path.exists():
        return capability_from_model(binary, json.loads(path.read_text(encoding="utf-8")))
    if (path.parent / f"{binary}.missing").exists():
        return None
    url = MODEL_URL.format(commit=commit, binary=binary)
    try:
        with urllib.request.urlopen(url, timeout=30.0) as response:
            data = response.read(MAX_MODEL_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            path.parent.mkdir(parents=True, exist_ok=True)
            (path.parent / f"{binary}.missing").write_text("", encoding="utf-8")
            return None
        raise ArgfuscatorFetchError(f"{binary}: HTTP {e.code}") from e
    if len(data) > MAX_MODEL_BYTES:
        raise ArgfuscatorFetchError(f"{binary}: model exceeds {MAX_MODEL_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return capability_from_model(binary, json.loads(data.decode("utf-8")))
