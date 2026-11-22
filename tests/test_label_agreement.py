"""Hard-negative label agreement: the blind sheet hides the answers, and labels are read strictly."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import label_agreement as la  # noqa: E402


@pytest.fixture(autouse=True)
def _in_repo(monkeypatch):
    monkeypatch.chdir(ROOT)


def test_every_hard_negative_is_an_item_with_its_attack_description():
    items = la.items()
    main = [i for i in items if i["set"] == "main"]
    assert len(main) >= 50 and all(i["dataset_label"] in ("A", "B") for i in main)
    assert all(i["attack"] for i in items), "every item needs the attack it resembles"
    assert len({i["id"] for i in items}) == len(items)


def test_the_sheet_never_shows_the_answers(tmp_path, monkeypatch):
    monkeypatch.setattr(la, "OUT", tmp_path)
    la.prepare(None)
    sheet = (tmp_path / "sheet.md").read_text(encoding="utf-8")
    for it in la.items():
        assert it["cmd"] in sheet
    assert "class:" not in sheet and "note:" not in sheet


def test_parse_labels():
    text = "# c\nT1027-n1  a  local hash\nT1027-n2  ?  \npilot-1  X  actually malicious\n"
    assert la.parse_labels(text) == {"T1027-n1": ("A", "local hash"), "pilot-1": ("X", "actually malicious")}


def test_kappa():
    assert la.cohen_kappa(list("AABB"), list("AABB")) == 1.0
    assert la.cohen_kappa(list("AABB"), list("ABAB")) == pytest.approx(0.0)
    assert la.cohen_kappa([], []) is None
