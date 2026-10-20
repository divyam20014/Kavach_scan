import hashlib
import json
from pathlib import Path

import pytest

from app.core.settings import RuntimeSettings
from app.models import (
    EvidenceMetadata,
    ImportArtifact,
    ReportMetadata,
    ScanJob,
    new_id,
)
from app.models.settings import AppSettings
from app.storage.errors import (
    AlreadyExistsError,
    CorruptRecordError,
    InvalidRecordError,
    RecordNotFoundError,
    RecordTooLargeError,
    RevisionConflictError,
)
from app.storage.repository import StorageRepository
from tests.conftest import make_asset, make_finding, make_project


def test_restart_persistence_reads_exact_data_back(settings: RuntimeSettings) -> None:
    """Acceptance: create project/findings/assets, restart repository, read exact data back."""
    with StorageRepository.open(settings) as repo:
        project = repo.create_project(make_project(labels=["external", "q4"]))
        pid = project.project_id
        findings = [
            repo.create_finding(make_finding(pid, title=f"Finding {i}", severity=s))
            for i, s in enumerate(["critical", "high", "low"])
        ]
        assets = [
            repo.create_asset(make_asset(pid, locator=f"host{i}.example.com")) for i in range(3)
        ]
        updated = repo.update_finding(pid, findings[0].finding_id, {"analyst_status": "confirmed"})

    with StorageRepository.open(settings) as reopened:  # new process-equivalent instance
        assert reopened.get_project(pid) == project
        assert reopened.get_finding(pid, updated.finding_id) == updated
        for f in findings[1:]:
            assert reopened.get_finding(pid, f.finding_id) == f
        for a in assets:
            assert reopened.get_asset(pid, a.asset_id) == a
        page = reopened.list_findings(pid, limit=10)
        assert page.total == 3 and not page.errors
        assert {f.finding_id for f in page.items} == {f.finding_id for f in findings}


def test_project_crud_and_revisions(repo: StorageRepository) -> None:
    project = repo.create_project(make_project())
    with pytest.raises(AlreadyExistsError):
        repo.create_project(project)
    updated = repo.update_project(project.project_id, {"name": "Renamed"}, expected_revision=1)
    assert updated.name == "Renamed" and updated.revision == 2
    assert updated.created_at == project.created_at and updated.updated_at >= project.updated_at
    with pytest.raises(RevisionConflictError):
        repo.update_project(project.project_id, {"name": "Stale"}, expected_revision=1)
    with pytest.raises(InvalidRecordError):  # validation re-runs on update
        repo.update_project(project.project_id, {"name": ""})
    with pytest.raises(InvalidRecordError):  # unknown keys rejected
        repo.update_project(project.project_id, {"db_password": "x"})
    # immutable fields cannot be changed through updates
    same = repo.update_project(
        project.project_id, {"project_id": new_id("project"), "created_at": "2000-01-01T00:00:00Z"}
    )
    assert same.project_id == project.project_id and same.created_at == project.created_at
    repo.delete_project(project.project_id)
    with pytest.raises(RecordNotFoundError):
        repo.get_project(project.project_id)
    with pytest.raises(RecordNotFoundError):
        repo.delete_project(project.project_id)
    assert not repo.paths.path("projects", project.project_id).exists()
    assert list(repo.paths.path("trash").iterdir()) == []


def test_children_require_existing_project(repo: StorageRepository) -> None:
    ghost = new_id("project")
    with pytest.raises(RecordNotFoundError):
        repo.create_finding(make_finding(ghost))
    with pytest.raises(RecordNotFoundError):
        repo.list_findings(ghost)
    assert not repo.paths.path("projects", ghost).exists()


def test_delete_project_removes_children(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    f = repo.create_finding(make_finding(pid))
    repo.save_evidence(
        EvidenceMetadata(
            evidence_id=new_id("evidence"), project_id=pid, evidence_type="text_excerpt"
        ),
        blob=b"abc",
    )
    repo.delete_project(pid)
    with pytest.raises(RecordNotFoundError):
        repo.get_finding(pid, f.finding_id)
    assert repo.list_projects().total == 0


def test_scan_finding_asset_crud(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    scan = repo.create_scan(ScanJob(scan_id=new_id("scan"), project_id=pid, module="web_app"))
    assert repo.update_scan(pid, scan.scan_id, {"state": "cancelled"}).state == "cancelled"
    with pytest.raises(InvalidRecordError):
        repo.update_scan(pid, scan.scan_id, {"state": "exploded"})
    finding = repo.create_finding(make_finding(pid, scan_id=scan.scan_id))
    with pytest.raises(AlreadyExistsError):
        repo.create_finding(finding)
    asset = repo.create_asset(make_asset(pid))
    assert (
        repo.update_asset(pid, asset.asset_id, {"scope_status": "excluded"}).scope_status
        == "excluded"
    )
    repo.delete_finding(pid, finding.finding_id)
    repo.delete_asset(pid, asset.asset_id)
    with pytest.raises(RecordNotFoundError):
        repo.get_finding(pid, finding.finding_id)
    with pytest.raises(RecordNotFoundError):
        repo.get_asset(pid, asset.asset_id)
    # a record stored under another project's id is not reachable
    other = repo.create_project(make_project()).project_id
    f2 = repo.create_finding(make_finding(other))
    with pytest.raises(RecordNotFoundError):
        repo.get_finding(pid, f2.finding_id)


def test_pagination_filters_and_sorting(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    severities = ["low", "critical", "medium", "high", "informational", "critical", "low"]
    for i, sev in enumerate(severities):
        repo.create_finding(make_finding(pid, title=f"F{i}", severity=sev))
    by_sev = repo.list_findings(pid, sort="severity", descending=False, limit=50)
    assert [f.severity for f in by_sev.items] == sorted(
        severities, key=["critical", "high", "medium", "low", "informational"].index
    )
    crit = repo.list_findings(pid, severity={"critical"})
    assert crit.total == 2 and all(f.severity == "critical" for f in crit.items)
    page1 = repo.list_findings(pid, sort="title", descending=False, offset=0, limit=3)
    page2 = repo.list_findings(pid, sort="title", descending=False, offset=3, limit=3)
    assert page1.total == page2.total == 7
    assert [f.title for f in page1.items + page2.items] == [f"F{i}" for i in range(6)]
    with pytest.raises(InvalidRecordError):
        repo.list_findings(pid, sort="__class__")
    with pytest.raises(InvalidRecordError):
        repo.list_findings(pid, limit=0)
    with pytest.raises(InvalidRecordError):
        repo.list_findings(pid, limit=10_000)


def test_project_search_and_status_filter(repo: StorageRepository) -> None:
    repo.create_project(make_project(name="Bank portal", client_name="First Bank"))
    archived = repo.create_project(
        make_project(name="Old site", client_name="Acme", status="archived")
    )
    assert [p.name for p in repo.list_projects(search="bank").items] == ["Bank portal"]
    assert [p.project_id for p in repo.list_projects(status="archived").items] == [
        archived.project_id
    ]
    assert repo.list_projects(search="ACME").total == 1


def test_corrupt_record_reported_without_breaking_unrelated_projects(
    repo: StorageRepository,
) -> None:
    good = repo.create_project(make_project(name="Good"))
    bad = repo.create_project(make_project(name="Bad"))
    good_finding = repo.create_finding(make_finding(good.project_id))
    bad_finding = repo.create_finding(make_finding(bad.project_id))
    repo.paths.path("projects", bad.project_id, "project.json").write_text('{"truncated": ')
    repo.paths.path(
        "projects", good.project_id, "findings", f"{good_finding.finding_id}.json"
    ).write_text("[]")

    listing = repo.list_projects()
    assert [p.name for p in listing.items] == ["Good"]
    assert [(e.record_id, e.kind) for e in listing.errors] == [(bad.project_id, "record_corrupt")]
    with pytest.raises(CorruptRecordError):
        repo.get_project(bad.project_id)

    findings = repo.list_findings(good.project_id)
    assert findings.items == [] and findings.errors[0].record_id == good_finding.finding_id
    # unrelated project's finding still fully readable
    assert repo.get_finding(bad.project_id, bad_finding.finding_id) == bad_finding


def test_schema_invalid_record_reported(repo: StorageRepository) -> None:
    project = repo.create_project(make_project())
    path = repo.paths.path("projects", project.project_id, "project.json")
    data = json.loads(path.read_text())
    data["scan_policy"]["max_concurrency"] = 500  # above the hard cap
    path.write_text(json.dumps(data))
    with pytest.raises(InvalidRecordError, match="max_concurrency"):
        repo.get_project(project.project_id)
    data["scan_policy"]["max_concurrency"] = 2
    data["schema_version"] = 99
    path.write_text(json.dumps(data))
    errors = repo.list_projects().errors
    assert errors and errors[0].kind == "schema_version_unsupported"


def test_record_moved_to_wrong_location_rejected(repo: StorageRepository) -> None:
    a = repo.create_project(make_project()).project_id
    b = repo.create_project(make_project()).project_id
    f = repo.create_finding(make_finding(a))
    src = repo.paths.path("projects", a, "findings", f"{f.finding_id}.json")
    dst_dir = repo.paths.path("projects", b, "findings")
    dst_dir.mkdir()
    (dst_dir / src.name).write_bytes(src.read_bytes())
    with pytest.raises(InvalidRecordError, match="does not match its location"):
        repo.get_finding(b, f.finding_id)


def test_evidence_redacted_and_blob_verified(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    ev = repo.save_evidence(
        EvidenceMetadata(
            evidence_id=new_id("evidence"),
            project_id=pid,
            evidence_type="http_exchange",
            request_excerpt="GET /?token=abc123secret HTTP/1.1\nAuthorization: Bearer eyJzzzzzzzzzz.yyyyyyyyy.xxxxx\nCookie: sid=s3cr3t",
            response_excerpt="HTTP/1.1 200 OK\nSet-Cookie: session=topsecretvalue",
        ),
        blob=b"\x00binary-evidence",
    )
    raw = repo.paths.path("projects", pid, "evidence", f"{ev.evidence_id}.json").read_text()
    for secret in ("abc123secret", "eyJzzzzzzzzzz", "s3cr3t", "topsecretvalue"):
        assert secret not in raw
    assert ev.has_blob and ev.blob_sha256 == hashlib.sha256(b"\x00binary-evidence").hexdigest()
    assert repo.read_evidence_blob(pid, ev.evidence_id) == b"\x00binary-evidence"
    repo.paths.path("projects", pid, "evidence", f"{ev.evidence_id}.bin").write_bytes(b"tampered")
    with pytest.raises(CorruptRecordError, match="hash mismatch"):
        repo.read_evidence_blob(pid, ev.evidence_id)
    repo.delete_evidence(pid, ev.evidence_id)
    assert not repo.paths.path("projects", pid, "evidence", f"{ev.evidence_id}.bin").exists()


def test_import_raw_stored_with_hash_check(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    raw = b"<nmaprun></nmaprun>"
    meta = ImportArtifact(
        import_id=new_id("import"),
        project_id=pid,
        display_filename="scan.xml",
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        source_type="nmap_xml",
    )
    with pytest.raises(InvalidRecordError):
        repo.create_import(meta, raw + b"x")
    stored = repo.create_import(meta, raw)
    assert repo.read_import_raw(pid, stored.import_id) == raw
    assert repo.update_import(pid, stored.import_id, {"status": "parsed"}).status == "parsed"
    assert repo.list_imports(pid, status={"parsed"}).total == 1


def test_report_metadata_and_settings(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    rpt = repo.save_report_metadata(
        ReportMetadata(
            report_id=new_id("report"), project_id=pid, title="Q4 report", formats=["html"]
        )
    )
    assert repo.get_report_metadata(pid, rpt.report_id) == rpt
    assert repo.list_reports(pid).total == 1
    current = repo.get_settings()
    saved = repo.save_settings(
        current.model_copy(update={"product_name": "Kavach"}), expected_revision=current.revision
    )
    assert saved.product_name == "Kavach" and saved.revision == current.revision + 1
    with pytest.raises(RevisionConflictError):
        repo.save_settings(AppSettings(), expected_revision=current.revision)


def test_oversized_record_rejected(repo: StorageRepository, tmp_path: Path) -> None:
    small = RuntimeSettings(data_dir=str(tmp_path / "other"), max_record_bytes=64 * 1024)
    with StorageRepository.open(small) as tiny:
        with pytest.raises(RecordTooLargeError):
            tiny.create_project(
                make_project(
                    description="x" * 19_000, notes="y" * 19_000, labels=["a"] * 50, name="n" * 200
                ).model_copy(
                    update={
                        "scope": make_project().scope.model_copy(
                            update={"hosts": [f"h{i}.example.com" for i in range(1000)]}
                        )
                    }
                )
            )
