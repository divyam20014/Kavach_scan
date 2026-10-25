"""Phase 10: report builder, export, and backup/restore HTTP routes."""

from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient

from app.storage.repository import StorageRepository
from tests.conftest import make_finding
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def test_preview_and_generate_agree_on_the_same_finding_set(
    client: TestClient, repo: StorageRepository
) -> None:
    """Acceptance criterion: "the same selected findings appear consistently in preview and
    files"."""
    pid = _project(repo)
    f1 = repo.create_finding(make_finding(pid, title="Keep", severity="high"))
    repo.create_finding(make_finding(pid, title="Drop", severity="low"))

    body = {"severity_threshold": "high"}
    preview = client.post(f"/api/projects/{pid}/reports/preview", json=body).json()
    assert preview["finding_ids"] == [f1.finding_id]

    generated = client.post(
        f"/api/projects/{pid}/reports", json={**body, "formats": ["html", "json"]}
    )
    assert generated.status_code == 201
    report_id = generated.json()["report_id"]
    detail = client.get(f"/api/projects/{pid}/reports/{report_id}").json()
    assert detail["finding_count"] == 1

    html = client.get(f"/api/projects/{pid}/reports/{report_id}/download/html")
    assert html.status_code == 200
    assert "Keep" in html.text
    assert "Drop" not in html.text

    findings_json = client.get(f"/api/projects/{pid}/reports/{report_id}/download/json").json()
    assert [f["title"] for f in findings_json["findings"]] == ["Keep"]


def test_download_rejects_a_format_that_was_not_generated(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    created = client.post(
        f"/api/projects/{pid}/reports", json={"formats": ["html"]}
    ).json()
    resp = client.get(f"/api/projects/{pid}/reports/{created['report_id']}/download/pdf")
    assert resp.status_code == 404


def test_pdf_download_is_a_real_pdf(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="PDF check finding"))
    created = client.post(
        f"/api/projects/{pid}/reports", json={"formats": ["pdf"]}
    ).json()
    resp = client.get(f"/api/projects/{pid}/reports/{created['report_id']}/download/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:5] == b"%PDF-"


def test_html_response_escapes_a_script_tag_in_the_title(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="<script>alert(1)</script>"))
    created = client.post(f"/api/projects/{pid}/reports", json={"formats": ["html"]}).json()
    html = client.get(
        f"/api/projects/{pid}/reports/{created['report_id']}/download/html"
    ).text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_standalone_exports_reflect_all_findings_by_default(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="E1"))
    repo.create_finding(make_finding(pid, title="E2"))
    j = client.get(f"/api/projects/{pid}/export/findings.json").json()
    assert j["count"] == 2
    csv_text = client.get(f"/api/projects/{pid}/export/findings.csv").text
    assert "E1" in csv_text and "E2" in csv_text


def test_backup_export_preview_restore_round_trip_via_api(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="Backed up finding"))
    export_resp = client.get(f"/api/projects/{pid}/backup/export")
    assert export_resp.status_code == 200
    assert export_resp.headers["content-type"] == "application/zip"
    archive = export_resp.content
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        assert "manifest.json" in zf.namelist()

    preview_resp = client.post(
        "/api/backup/preview", files={"file": ("backup.zip", archive, "application/zip")}
    )
    assert preview_resp.status_code == 200
    preview = preview_resp.json()
    assert preview["project_already_exists"] is True
    assert preview["counts"]["findings"] == 1
    assert preview["checksum_mismatches"] == []

    # restoring into the same repo without overwrite must be refused (preserve current data)
    conflict = client.post(
        "/api/backup/restore",
        params={"confirmed": True, "overwrite": False},
        files={"file": ("backup.zip", archive, "application/zip")},
    )
    assert conflict.status_code == 409
    assert repo.list_findings(pid).items[0].title == "Backed up finding"

    overwritten = client.post(
        "/api/backup/restore",
        params={"confirmed": True, "overwrite": True},
        files={"file": ("backup.zip", archive, "application/zip")},
    )
    assert overwritten.status_code == 200
    assert overwritten.json()["counts"]["findings"] == 1


def test_backup_restore_without_confirmation_is_rejected(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    archive = client.get(f"/api/projects/{pid}/backup/export").content
    resp = client.post(
        "/api/backup/restore",
        params={"confirmed": False},
        files={"file": ("backup.zip", archive, "application/zip")},
    )
    assert resp.status_code == 422


def test_backup_preview_rejects_a_malicious_archive(client: TestClient) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "pwned")
    resp = client.post(
        "/api/backup/preview",
        files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
    )
    assert resp.status_code == 422


def test_audit_records_report_generation_download_and_backup(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    created = client.post(f"/api/projects/{pid}/reports", json={"formats": ["html"]}).json()
    client.get(f"/api/projects/{pid}/reports/{created['report_id']}/download/html")
    client.get(f"/api/projects/{pid}/backup/export")
    audit = client.get("/api/audit", params={"project_id": pid}).json()
    actions = [e["action"] for e in audit["items"]]
    assert "report_generated" in actions
    assert "report_downloaded" in actions
    assert "backup_created" in actions
