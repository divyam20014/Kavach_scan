"""Phase 07 API routes: spec upload/list/detail/validate and the scan-plan preview."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.storage.repository import StorageRepository
from tests.apifixtures import OPENAPI3_JSON, SWAGGER2_JSON, as_bytes
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(
        surface_project([443], hosts=["api.shop.test"], allowed_modules=["api_security"])
    ).project_id


def _upload(client: TestClient, pid: str, doc: dict, name: str = "spec.json") -> dict:
    resp = client.post(
        f"/api/projects/{pid}/api-specs", files={"file": (name, as_bytes(doc), "application/json")}
    )
    return resp.json() if resp.status_code == 201 else {"_status": resp.status_code, **resp.json()}


def test_upload_parses_and_inventories_offline(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    body = _upload(client, pid, OPENAPI3_JSON)
    assert body["summary"]["kind"] == "openapi3"
    assert body["summary"]["operation_count"] == 4
    keys = {o["key"] for o in body["inventory"]["operations"]}
    assert "GET /orders/{orderId}" in keys
    # the shop server is in scope (host api.shop.test), reported as such
    assert body["servers"][0]["in_scope"] is True
    # audit recorded
    audit = client.get("/api/audit", params={"project_id": pid}).json()
    assert any(e["action"] == "import_created" for e in audit["items"])


def test_upload_rejects_non_spec(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    resp = client.post(
        f"/api/projects/{pid}/api-specs",
        files={"file": ("x.json", b'{"hello":"world"}', "application/json")},
    )
    assert resp.status_code == 422
    resp = client.post(
        f"/api/projects/{pid}/api-specs",
        files={"file": ("x.json", b"{not json", "application/json")},
    )
    assert resp.status_code == 422


def test_list_and_detail(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    created = _upload(client, pid, OPENAPI3_JSON)
    import_id = created["summary"]["import_id"]
    listed = client.get(f"/api/projects/{pid}/api-specs").json()
    assert len(listed) == 1 and listed[0]["import_id"] == import_id
    detail = client.get(f"/api/projects/{pid}/api-specs/{import_id}").json()
    assert detail["summary"]["operation_count"] == 4
    assert client.get(f"/api/projects/{pid}/api-specs/imp_{'0' * 32}").status_code == 404


def test_validate_reports_servers_and_refs(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    import_id = _upload(client, pid, OPENAPI3_JSON)["summary"]["import_id"]
    validate = client.get(f"/api/projects/{pid}/api-specs/{import_id}/validate").json()
    assert validate["valid"] and validate["kind"] == "openapi3"
    assert "https://api.shop.test/v1" in validate["in_scope_servers"]
    # swagger spec whose server is out of scope
    sid = _upload(client, pid, SWAGGER2_JSON)["summary"]["import_id"]
    v2 = client.get(f"/api/projects/{pid}/api-specs/{sid}/validate").json()
    assert "https://legacy.test/api" in v2["out_of_scope_servers"]


def test_scan_plan_validates_params_and_server_scope(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    import_id = _upload(client, pid, OPENAPI3_JSON)["summary"]["import_id"]
    ok = client.post(
        f"/api/projects/{pid}/api-security-plan",
        json={"import_id": import_id, "inventory_only": True},
    ).json()
    assert ok["problems"] == [] and ok["operations_total"] == 4
    # IDOR without identities -> problems
    bad = client.post(
        f"/api/projects/{pid}/api-security-plan",
        json={"import_id": import_id, "enable_idor": True, "risk_ack": True},
    ).json()
    assert any("identit" in p for p in bad["problems"])
    # out-of-scope server flagged
    plan = client.post(
        f"/api/projects/{pid}/api-security-plan",
        json={
            "import_id": import_id,
            "inventory_only": False,
            "server_url": "https://evil.test/v1",
        },
    ).json()
    assert plan["server_in_scope"] is False


def test_api_module_available(client: TestClient) -> None:
    modules = {m["module"]: m for m in client.get("/api/jobs/modules").json()}
    assert modules["api_security"]["available"] is True
