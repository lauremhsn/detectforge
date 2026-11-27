"""SIEM parity script: events become ECS documents with the fields the exported queries use."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import elastic_parity as ep

from detectforge.schemas import Event


def test_event_becomes_an_ecs_document():
    e = Event(
        event_id="a1", image=r"C:\Windows\System32\reg.exe", command_line=r"reg save HKLM\sam x",
        parent_image=r"C:\Windows\System32\cmd.exe", original_file_name="reg.exe", label="attack",
        technique="T1003.002", transform="none", base_id="a1", split="tune",
    )  # fmt: skip
    doc = ep.doc_of(e)
    assert doc["process"]["executable"].endswith("reg.exe")
    assert doc["process"]["command_line"] == r"reg save HKLM\sam x"
    assert doc["process"]["pe"]["original_file_name"] == "reg.exe"
    assert doc["process"]["parent"]["executable"].endswith("cmd.exe")
    assert "command_line" not in doc["process"]["parent"]  # not captured: left out, not empty


def test_executables_are_also_searchable_case_insensitively():
    props = ep.MAPPING["mappings"]["properties"]["process"]["properties"]
    assert props["executable"]["fields"]["caseless"]["normalizer"] == "lowercase"
    assert props["command_line"]["type"] == "wildcard"
