"""Base attack command lines from Atomic Red Team test definitions, pinned to one commit.

Test YAML comes from an external repository and is untrusted input: it is parsed with safe_load,
size-limited, and only ever used as data.
"""

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

ART_COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
ART_RAW_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{commit}/atomics/{t}/{t}.yaml"
MAX_YAML_BYTES = 1024 * 1024

SYSTEM32 = "C:\\Windows\\System32\\"
CMD = SYSTEM32 + "cmd.exe"
POWERSHELL = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
PARENTS = {"command_prompt": CMD, "powershell": POWERSHELL}

# cmd and PowerShell expand these before the process starts, so Sysmon records the expanded value.
# The user profile is a placeholder; VM captures replace these events with real values.
USER_PROFILE = "C:\\Users\\analyst"
EXPANSIONS = [
    (r"PathToAtomicsFolder", "C:\\AtomicRedTeam\\atomics"),
    (r"%temp%|\$env:temp", USER_PROFILE + "\\AppData\\Local\\Temp"),
    (r"%localappdata%", USER_PROFILE + "\\AppData\\Local"),
    (r"%appdata%", USER_PROFILE + "\\AppData\\Roaming"),
    (r"%windir%", "C:\\Windows"),
    (r"%programfiles%", "C:\\Program Files"),
    (r"\(Get-Process lsass\)\.id", "692"),
]
SHELL_BUILTINS = {"echo", "cd", "set", "if", "for", "copy", "del", "type", "md", "mkdir", "start"}
_BINARY = re.compile(r"[a-z0-9_.\-]+")


class AtomicFetchError(RuntimeError):
    """A test definition could not be downloaded or is over the size limit."""


@dataclass(frozen=True)
class AtomicCommand:
    technique: str
    test_name: str
    command_line: str
    image: str
    parent_image: str


def expand(command: str) -> str:
    for pattern, value in EXPANSIONS:
        command = re.sub(pattern, lambda _m, v=value: v, command, flags=re.IGNORECASE)
    return command


def load_tests(
    technique: str, cache_dir: Path, commit: str = ART_COMMIT, timeout_s: float = 30.0
) -> dict | None:
    """Test definitions for one technique (cached on disk), or None if Atomic Red Team has none."""
    path = cache_dir / commit / f"{technique}.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    url = ART_RAW_URL.format(commit=commit, t=technique)
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as response:
            data = response.read(MAX_YAML_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise AtomicFetchError(f"{technique}: HTTP {e.code}") from e
    if len(data) > MAX_YAML_BYTES:
        raise AtomicFetchError(f"{technique}: definition exceeds {MAX_YAML_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return yaml.safe_load(data)


def windows_commands(doc: dict) -> list[AtomicCommand]:
    """One entry per line of a Windows cmd/PowerShell test that starts an external binary."""
    out = []
    for test in doc.get("atomic_tests") or []:
        executor = test.get("executor") or {}
        kind = executor.get("name")
        if "windows" not in (test.get("supported_platforms") or []) or kind not in PARENTS:
            continue
        command = executor.get("command") or ""
        for name, arg in (test.get("input_arguments") or {}).items():
            command = command.replace("#{" + name + "}", str((arg or {}).get("default", "")))
        for line in command.splitlines():
            parsed = _process_line(line.strip(), kind)
            if parsed:
                cmdline, image = parsed
                out.append(
                    AtomicCommand(doc["attack_technique"], test["name"], cmdline, image, PARENTS[kind])
                )
    return out


def _process_line(line: str, kind: str) -> tuple[str, str] | None:
    if not line or line.startswith(("#", "$")) or line.lower().startswith("rem ") or "#{" in line:
        return None
    token = line.split()[0].strip('"')
    name = token.split("\\")[-1].lower()
    if not _BINARY.fullmatch(name) or name in SHELL_BUILTINS:
        return None
    if not name.endswith(".exe"):
        if "." in name or (kind == "powershell" and "-" in name):
            return None
        name += ".exe"
    if "\\" in token and token.lower().endswith(".exe"):
        image = expand(token)
    else:
        image = POWERSHELL if name == "powershell.exe" else SYSTEM32 + name
    return expand(line), image
