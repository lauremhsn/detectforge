"""SigmaHQ reference index: building from a release zip and searching it (no network)."""

import json
import zipfile

import pytest

from detectforge.cli import main
from detectforge.config import get_settings
from detectforge.reference import sigmahq
from detectforge.reference.index import ReferenceIndex, techniques_from_tags
from detectforge.reference.sigmahq import ReleaseIntegrityError, build_index, verify_sha256


def rule_doc(
    rule_id: str,
    title: str,
    tags: list[str],
    detection: str = "  sel:\n    Image|endswith: '\\schtasks.exe'\n  condition: sel",
    category: str = "process_creation",
    status: str = "test",
) -> str:
    tag_lines = "".join(f"  - {t}\n" for t in tags) or "  []\n"
    return (
        f"title: {title}\nid: {rule_id}\nstatus: {status}\ndescription: {title}\n"
        f"tags:\n{tag_lines}"
        f"logsource:\n  category: {category}\n  product: windows\n"
        f"detection:\n{detection}\nfalsepositives:\n  - Admin activity\nlevel: medium\n"
    )


RULES = {
    "rules/windows/process_creation/schtasks_create.yml": rule_doc(
        "00000000-0000-4000-8000-000000000001",
        "Scheduled Task Creation Via Schtasks",
        ["attack.persistence", "attack.t1053.005"],
        "  sel:\n    Image|endswith: '\\schtasks.exe'\n    CommandLine|contains: '/create'\n  condition: sel",
    ),
    "rules/windows/process_creation/schtasks_parent.yml": rule_doc(
        "00000000-0000-4000-8000-000000000002",
        "Scheduled Task Generic",
        ["attack.t1053"],
        "  sel:\n    User: 'SYSTEM'\n  condition: sel",
    ),
    "rules-emerging-threats/2024/Malware/apt_tasks.yml": rule_doc(
        "00000000-0000-4000-8000-000000000003",
        "Some APT Scheduled Task Creation",
        ["attack.t1053.005", "attack.t1059.001", "attack.t1105"],
    ),
    "rules/windows/process_creation/certutil.yml": rule_doc(
        "00000000-0000-4000-8000-000000000004",
        "File Download Via Certutil",
        ["attack.t1105"],
        "  sel:\n    Image|endswith: '\\certutil.exe'\n"
        "    CommandLine|contains: 'urlcache'\n  condition: sel",
    ),
    "rules-emerging-threats/2024/Malware/untagged_tasks.yml": rule_doc(
        "00000000-0000-4000-8000-000000000005", "Malware Schedule Task Creation", []
    ),
    "rules/windows/process_creation/fieldref.yml": rule_doc(
        "00000000-0000-4000-8000-000000000006",
        "Fieldref Rule",
        ["attack.t1036"],
        "  sel:\n    CommandLine|fieldref: Image\n  condition: sel",
    ),
    "rules/windows/registry/reg.yml": rule_doc(
        "00000000-0000-4000-8000-000000000007", "Registry Rule", ["attack.t1112"], category="registry_set"
    ),
    "deprecated/old.yml": rule_doc(
        "00000000-0000-4000-8000-000000000008", "Old Rule", ["attack.t1053.005"], status="deprecated"
    ),
    "rules/windows/process_creation/broken.yml": "title: [unclosed",
    "rules/windows/process_creation/not_sigma.yml": rule_doc(
        "not-a-uuid", "Bad Id", ["attack.t1105"], "  condition: nothing"
    ),
    "README.md": "not a rule",
}


@pytest.fixture
def release_zip(tmp_path):
    path = tmp_path / "rules.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in RULES.items():
            zf.writestr(name, text)
    return path


@pytest.fixture
def index(release_zip, tmp_path) -> ReferenceIndex:
    build_index(release_zip, tmp_path / "idx", release="test-release")
    return ReferenceIndex.load(tmp_path / "idx")


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DETECTFORGE_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    yield tmp_path / "data"
    get_settings.cache_clear()


def ids(hits):
    return [h.rule.id[-1] for h in hits]


def test_build_index_filters_scope_and_reports_skips(release_zip, tmp_path):
    meta = build_index(release_zip, tmp_path / "idx", release="test-release")
    assert meta == {
        "format": 2,
        "release": "test-release",
        "rules_indexed": 6,
        "evaluable": 5,
        "usable": 4,
        "uses_missing_fields": 1,
        "skipped": {"excluded_status": 1, "invalid_sigma": 1, "invalid_yaml": 1},
    }


def test_index_records_harness_compatibility(index):
    by_id = {r.id[-1]: r for r in index.rules}
    assert by_id["2"].unmapped_fields == ["User"]
    assert not by_id["2"].can_fire and not by_id["2"].usable  # depends only on a missing field
    assert by_id["1"].usable
    assert not by_id["6"].evaluable and "unsupported" in by_id["6"].harness_error
    assert by_id["1"].techniques == ["T1053.005"]
    assert "schtasks" in by_id["1"].rule_yaml
    assert index.release == "test-release"


def test_search_by_technique_ranks_exact_then_related(index):
    hits = index.search(technique="T1053.005")
    assert ids(hits) == ["1", "3", "2"]
    assert [h.match for h in hits] == ["technique", "technique", "related_technique"]


def test_focused_core_rule_beats_campaign_rule_on_ties(index):
    hits = index.search(technique="T1053.005", limit=2)
    assert ids(hits) == ["1", "3"]  # same score; core rule with one technique wins


def test_query_reorders_and_finds_untagged(index):
    assert ids(index.search(query="certutil"))[0] == "4"
    assert "5" in ids(index.search(query="schedule task creation"))


def test_exclude_technique_drops_family_and_untagged_rules(index):
    hits = index.search(query="scheduled task creation schtasks", limit=20, exclude_technique="T1053.005")
    assert not {"1", "2", "3", "5"} & set(ids(hits))


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"technique": "1053"}, {"query": "x", "exclude_technique": "bad"}, {"query": "x", "limit": 0}],
)
def test_search_rejects_bad_arguments(index, kwargs):
    with pytest.raises(ValueError):
        index.search(**kwargs)


def test_techniques_from_tags():
    assert techniques_from_tags(["attack.t1053.005", "attack.persistence", "attack.T1105", "car.x"]) == [
        "T1053.005",
        "T1105",
    ]


def test_verify_sha256_rejects_tampered_release():
    with pytest.raises(ReleaseIntegrityError):
        verify_sha256(b"tampered", sigmahq.RELEASE_SHA256)


def test_missing_index_has_actionable_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="sigmahq fetch"):
        ReferenceIndex.load(tmp_path)


def test_old_index_format_must_be_rebuilt(release_zip, tmp_path):
    build_index(release_zip, tmp_path, release="test-release")
    (tmp_path / "meta.json").write_text(json.dumps({"release": "test-release"}), encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="old format"):
        ReferenceIndex.load(tmp_path)


def test_cli_fetch_refuses_unpinned_zip(release_zip, data_dir, capsys):
    assert main(["sigmahq", "fetch", "--zip", str(release_zip)]) == 1
    assert "sha256 mismatch" in capsys.readouterr().err


def test_cli_search(release_zip, data_dir, monkeypatch, capsys):
    monkeypatch.setattr(
        sigmahq, "RELEASE_SHA256", sigmahq.hashlib.sha256(release_zip.read_bytes()).hexdigest()
    )
    assert main(["sigmahq", "fetch", "--zip", str(release_zip)]) == 0
    capsys.readouterr()
    assert main(["sigmahq", "search", "--technique", "T1105"]) == 0
    hits = json.loads(capsys.readouterr().out)
    assert hits[0]["rule"]["title"] == "File Download Via Certutil"
    assert "rule_yaml" not in hits[0]["rule"]
