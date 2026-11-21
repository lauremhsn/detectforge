from pathlib import Path

from detectforge.dataset.hard_negatives import HardNegatives, _image_and_parent, build_events, load

CONFIG = HardNegatives.model_validate(
    {
        "negatives": {
            "T1490": [
                {"class": "A", "note": "listing, not deleting", "cmd": "vssadmin list shadows"},
                {
                    "class": "B",
                    "note": "backup tools do the same",
                    "cmd": "vssadmin delete shadows /all /quiet",
                },
            ],
            "T1059.001": [
                {"class": "A", "note": "ordinary ps", "cmd": 'powershell.exe -Command "Get-Process"'},
            ],
        }
    }
)


def test_image_and_parent_system32_binary():
    assert _image_and_parent("vssadmin list shadows") == (
        "C:\\Windows\\System32\\vssadmin.exe",
        "C:\\Windows\\System32\\cmd.exe",
    )


def test_image_and_parent_powershell():
    image, parent = _image_and_parent('powershell.exe -Command "x"')
    assert image.endswith("WindowsPowerShell\\v1.0\\powershell.exe")
    assert parent == image


def test_image_and_parent_quoted_full_path():
    image, _ = _image_and_parent('"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -SignatureUpdate')
    assert image == "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"


def test_build_events_splits_by_class():
    class_a, class_b = build_events(CONFIG)
    assert [e.command_line for e in class_a] == [
        "vssadmin list shadows",
        'powershell.exe -Command "Get-Process"',
    ]
    assert [e.command_line for e in class_b] == ["vssadmin delete shadows /all /quiet"]


def test_build_events_sets_benign_fields():
    class_a, class_b = build_events(CONFIG)
    for e in class_a + class_b:
        assert e.label == "benign"
        assert e.transform == "none"
        assert e.split == "heldout"
        assert e.base_id == e.event_id
    assert class_a[0].event_id == "T1490-na1"
    assert class_b[0].event_id == "T1490-nb1"
    assert class_a[0].technique == "T1490"


def test_loads_the_committed_config():
    config = load(Path("data/eval/hard_negatives.yml"))
    class_a, class_b = build_events(config)
    assert len(class_a) == 52
    assert len(class_b) == 6
    tune = [e for e in class_a if e.split == "tune"]
    assert len(tune) == 18 and all(e.split == "tune" and e.label == "benign" for e in tune)
    # every class B is tagged with a reason it can't be told from the attack by command line
    for entries in config.negatives.values():
        for entry in entries:
            assert entry.note
            assert entry.hn_class in ("A", "B")
