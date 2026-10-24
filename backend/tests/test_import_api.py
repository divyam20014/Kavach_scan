"""Phase 08 API routes: upload -> dry-run preview -> explicit commit; provenance, audit,
double-commit rejection, and the formats listing."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.storage.repository import StorageRepository
from tests import importfixtures as fx
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def test_upload_returns_preview_without_committing(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    resp = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("export.json", fx.GENERIC_JSON, "application/json")},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["error"] == ""
    assert body["summary"]["source_type"] == "generic_json"
    assert body["summary"]["status"] == "parsed"
    assert body["preview"]["parsed_count"] == 1
    assert repo.list_findings(pid).total == 0  # preview never writes canonical findings
    audit = client.get("/api/audit", params={"project_id": pid}).json()
    assert any(e["action"] == "import_created" for e in audit["items"])


def test_upload_rejects_unparseable_file_but_still_records_the_attempt(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    resp = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("mystery.bin", b"\x00garbage not a known format", "application/octet-stream")},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["error"]
    assert body["summary"]["status"] == "parse_failed"
    assert body["preview"] is None


def test_list_and_detail(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    created = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("scan.xml", fx.NMAP_XML, "application/xml")},
    ).json()
    import_id = created["summary"]["import_id"]
    listed = client.get(f"/api/projects/{pid}/imports").json()
    assert len(listed) == 1 and listed[0]["import_id"] == import_id
    detail = client.get(f"/api/projects/{pid}/imports/{import_id}").json()
    assert detail["summary"]["source_type"] == "nmap_xml"
    assert detail["preview"]["parsed_count"] >= 1


def test_commit_creates_findings_and_rejects_a_second_commit(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    created = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("export.json", fx.GENERIC_JSON, "application/json")},
    ).json()
    import_id = created["summary"]["import_id"]
    revision = repo.get_import(pid, import_id).revision
    resp = client.post(
        f"/api/projects/{pid}/imports/{import_id}/commit",
        json={"confirmed": True, "expected_revision": revision},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_created"] == 1
    assert repo.list_findings(pid).total == 1
    stored = repo.list_findings(pid).items[0]
    assert stored.sources[0].import_id == import_id
    assert stored.sources[0].tool == "Generic JSON"

    # a second commit of the same import must be rejected, not silently re-applied
    resp2 = client.post(
        f"/api/projects/{pid}/imports/{import_id}/commit",
        json={"confirmed": True, "expected_revision": revision},
    )
    assert resp2.status_code == 409
    assert repo.list_findings(pid).total == 1  # unchanged


def test_commit_requires_explicit_confirmation(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    created = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("export.json", fx.GENERIC_JSON, "application/json")},
    ).json()
    import_id = created["summary"]["import_id"]
    revision = repo.get_import(pid, import_id).revision
    resp = client.post(
        f"/api/projects/{pid}/imports/{import_id}/commit",
        json={"confirmed": False, "expected_revision": revision},
    )
    assert resp.status_code == 422
    assert repo.list_findings(pid).total == 0


def test_csv_column_map_override_round_trips_through_upload_and_detail(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    raw = b"Col A,Col B\r\nfoo,bar\r\n"
    created = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("weird.csv", raw, "text/csv")},
        data={"source_type": "generic_csv", "options_json": json.dumps({"column_map": {"title": "Col A"}})},
    ).json()
    assert created["error"] == ""
    import_id = created["summary"]["import_id"]
    assert created["preview"]["records"][0]["title"] == "foo"
    # re-GET must reproduce the identical parse using the stored options, without re-supplying them
    detail = client.get(f"/api/projects/{pid}/imports/{import_id}").json()
    assert detail["preview"]["records"][0]["title"] == "foo"


def test_formats_endpoint_lists_supported_and_unsupported() -> None:
    import app.main as main_mod

    client = TestClient(main_mod.create_app(), base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT)
    body = client.get("/api/imports/formats").json()
    types = {f["source_type"] for f in body["supported"]}
    assert {"nmap_xml", "nessus", "nuclei_jsonl", "sarif", "generic_csv", "generic_json",
           "pdf_text"} <= types
    assert {"zap", "burp"} == {f["source_type"] for f in body["unsupported"]}
    assert all(f["reason"] for f in body["unsupported"])


def test_404_for_unknown_import(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    resp = client.get(f"/api/projects/{pid}/imports/imp_{'0' * 32}")
    assert resp.status_code == 404


def test_commit_of_unknown_import_is_404(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    resp = client.post(
        f"/api/projects/{pid}/imports/imp_{'0' * 32}/commit",
        json={"confirmed": True, "expected_revision": 1},
    )
    assert resp.status_code == 404
    assert repo.list_findings(pid).total == 0


def test_commit_with_stale_revision_is_409(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    created = client.post(
        f"/api/projects/{pid}/imports",
        files={"file": ("export.json", fx.GENERIC_JSON, "application/json")},
    ).json()
    import_id = created["summary"]["import_id"]
    resp = client.post(
        f"/api/projects/{pid}/imports/{import_id}/commit",
        json={"confirmed": True, "expected_revision": 999},
    )
    assert resp.status_code == 409
    assert repo.list_findings(pid).total == 0
