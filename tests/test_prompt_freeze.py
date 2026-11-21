"""Frozen prompts: the text an evaluation arm was run with may not change under the same version.

Test-technique results are only fair if the prompt was fixed before they were run. Once a version is
frozen here, editing its text fails this test: give the change a new version number instead (and
re-run what used the old one), so every saved run's prompt_version still names the text it used.
"""

import hashlib

import pytest

from detectforge.agent import loop

# version -> sha256 of the system prompt, plus the two reminders the loop may send during a run.
FROZEN = {
    "harden-v7": {  # frozen Nov 22, before the test-technique runs
        "SYSTEM_PROMPT": "cd93c79910b9f649de7b477bb5e313713e92e9f51d4b7a95d06dbe32c08ab1aa",
        "NUDGE": "9b961d3204bf168becbedc6f4b47dcafcdb01eb540770d4c0576fcd57bfd3b2c",
        "CUT_OFF_NUDGE": "6af58b07b8b1b2631a6201f5fa46535faa09f99857e97cdf1956e58893dfb009",
    },
    "write-v2": {  # frozen Nov 18, after the dev write runs (no copied characters, every run submitted)
        "WRITE_SYSTEM_PROMPT": "1033dc6a05f9174e1261d19273c2788aac0708e289bbbbaaaa0eeeadb53dca1a",
        "NUDGE": "9b961d3204bf168becbedc6f4b47dcafcdb01eb540770d4c0576fcd57bfd3b2c",
        "CUT_OFF_NUDGE": "6af58b07b8b1b2631a6201f5fa46535faa09f99857e97cdf1956e58893dfb009",
    },
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.mark.parametrize("version", sorted(FROZEN))
def test_a_frozen_prompt_is_unchanged(version):
    current = {loop.PROMPT_VERSION, loop.WRITE_PROMPT_VERSION}
    assert version in current, f"{version} is frozen but no longer the current version; move it here"
    changed = [name for name, sha in FROZEN[version].items() if _sha(getattr(loop, name)) != sha]
    assert not changed, (
        f"{version} is frozen, but {', '.join(changed)} changed. Give the new text a new version "
        "number (and add it here once it is frozen) instead of editing a frozen one."
    )
