from app.models import EvidenceMetadata, new_id
from app.storage.integrity import check_integrity
from app.storage.repository import StorageRepository
from tests.conftest import make_asset, make_finding, make_project


def _kinds(report) -> list[str]:  # type: ignore[no-untyped-def]
    return sorted(i.kind for i in report.issues)


def test_clean_repository_has_no_issues(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    ev = repo.save_evidence(
        EvidenceMetadata(
            evidence_id=new_id("evidence"), project_id=pid, evidence_type="text_excerpt"
        ),
        blob=b"x",
    )
    repo.create_finding(make_finding(pid, evidence_ids=[ev.evidence_id]))
    report = check_integrity(repo, repair=False)
    assert report.ok, report.issues
    assert report.projects_checked == 1 and report.records_checked == 3


def test_detects_problems_without_deleting_data(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    ev = repo.save_evidence(
        EvidenceMetadata(
            evidence_id=new_id("evidence"), project_id=pid, evidence_type="text_excerpt"
        ),
        blob=b"x",
    )
    repo.create_finding(make_finding(pid, evidence_ids=[new_id("evidence")]))  # dangling
    asset = repo.create_asset(make_asset(pid))
    corrupt = repo.paths.path("projects", pid, "assets", f"{asset.asset_id}.json")
    corrupt.write_text("{oops")
    repo.paths.path("projects", pid, "evidence", f"{ev.evidence_id}.bin").unlink()  # missing blob
    orphan = repo.paths.path("projects", pid, "evidence", f"{new_id('evidence')}.bin")
    orphan.write_bytes(b"orphan")
    (repo.paths.path("projects") / "random-folder").mkdir()
    tmp = repo.paths.path("projects", pid) / ".project.json.0123456789ab.tmp"
    tmp.write_text("partial")

    report = check_integrity(repo, repair=False)
    assert _kinds(report) == sorted(
        [
            "dangling_evidence_ref",
            "corrupt_record",
            "missing_blob",
            "orphan_blob",
            "unexpected_entry",
            "temp_file",
        ]
    )
    assert all(not i.location.startswith(("/", "C:", "\\")) for i in report.issues)  # relative only
    assert corrupt.exists() and orphan.exists() and tmp.exists()  # nothing deleted in check mode

    repaired = check_integrity(repo, repair=True)
    assert repaired.temp_files_removed == 1 and not tmp.exists()
    assert repaired.indexes_rebuilt >= 1
    assert corrupt.exists() and orphan.exists()  # canonical/unknown data is never auto-deleted
    assert "temp_file" not in _kinds(repaired)


def test_interrupted_project_delete_is_reported(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    (repo.paths.path("projects", pid) / ".deleting").write_text("1")
    report = check_integrity(repo, repair=False)
    assert _kinds(report) == ["project_pending_delete"]
