"""Agent-written rules get their id, status, author and date from code, not from the model."""

from datetime import date

import yaml

from detectforge.rules.stamp import AUTHOR, rule_id, stamp_written_rule
from detectforge.rules.validate import validate_rule

TODAY = date(2026, 11, 18)
TRACE = "8e3abcbe" + "0" * 24

# Shape of a real write-v2 rule: a made-up id, a placeholder author and an old date.
WRITTEN = """\
title: "Persistence via Registry Run Keys (T1547.001)"
id: "d4e1a3f2-8b4c-4f7a-9d2e-1c5b6a7e8f90"
status: test
description: Detects modification of Windows registry run keys via reg.exe.
author:
  - "Detection Engineer"
date: "2024-01-15"
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\\reg.exe'
    - OriginalFileName: 'reg.exe'
  selection_add:
    CommandLine|re: '(?i)\\badd\\b'
  condition: selection_img and selection_add
falsepositives:
  - Software installers
level: high
"""


def test_metadata_is_set_by_code_and_detection_is_untouched():
    stamped = stamp_written_rule(WRITTEN, TRACE, TODAY)
    rule, original = yaml.safe_load(stamped), yaml.safe_load(WRITTEN)
    assert rule["id"] == rule_id(TRACE) != original["id"]
    assert (rule["author"], rule["status"], str(rule["date"])) == (AUTHOR, "experimental", "2026-11-18")
    assert rule["detection"] == original["detection"] and rule["title"] == original["title"]
    assert "Detection Engineer" not in stamped
    assert "CommandLine|re: '(?i)\\badd\\b'" in stamped  # detection lines kept byte for byte
    assert validate_rule(stamped).valid


def test_the_same_run_always_gets_the_same_id():
    assert stamp_written_rule(WRITTEN, TRACE, TODAY) == stamp_written_rule(WRITTEN, TRACE, TODAY)
    assert rule_id(TRACE) != rule_id("1" * 32)


def test_missing_metadata_is_added():
    bare = "\n".join(
        line for line in WRITTEN.splitlines() if not line.startswith(("id:", "status:", "date:"))
    )
    rule = yaml.safe_load(stamp_written_rule(bare, TRACE, TODAY))
    assert rule["id"] == rule_id(TRACE) and rule["status"] == "experimental"


def test_a_rule_that_cannot_be_stamped_safely_is_left_as_it_is():
    for text in ("not: [valid", "just a string", "title: x\ndetection: {}\n"):
        assert stamp_written_rule(text, TRACE, TODAY) == text
