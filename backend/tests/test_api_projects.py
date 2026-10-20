"""Phase 02 API: projects, scope preview, dashboard, drill-down lists, audit, UI serving."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.main import create_app
from app.models import ScanJob, new_id
from app.storage.repository import StorageRepository
from app.web import mount_ui
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT, make_asset, make_finding

NOW = datetime.now(UTC)


def _auth(**overrides: Any) -> dict[str, Any]:
    data = {
        "organization": "Acme Corp",
        "target_owner": "Acme IT",
        "authorized_by": "CISO Jane Doe",
        "reference": "SOW-2026-17",
        "window_start": (NOW - timedelta(days=1)).isoformat(),
        "window_end": (NOW + timedelta(days=30)).isoformat(),
        "attestation": True,
    }
    data.update(overrides)
    return data


def _create(client: TestClient, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Web assessment",
        "client_name": "Acme Corp",
        "authorization": _auth(),
        "scope": {"hosts": ["app.example.com"], "schemes": ["https"], "ports": [443]},
    }
    body.update(overrides)
    resp = client.post("/api/projects", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


# ------------------------------------------------------------------ create / read / update


def test_create_project_persists_and_records_attestation(
    client: TestClient, repo: StorageRepository
) -> None:
    project = _create(client)
    pid = project["project_id"]
    assert project["authorization"]["attestation_event_id"].startswith("evt_")
    overview = client.get(f"/api/projects/{pid}").json()
    assert overview["authorization_status"] == "active"
    assert overview["last_scan"] is None
    assert overview["counts"] == {
        "scan": 0,
        "finding": 0,
        "asset": 0,
        "evidence": 0,
        "import": 0,
        "report": 0,
    }
    actions = [e.action for e in repo.audit.list(project_id=pid).items]
    assert actions == ["project_created", "authorization_attested"]
    attest = repo.audit.list(project_id=pid, action="authorization_attested").items[0]  # type: ignore[arg-type]
    assert attest.metadata["label"] == "operator attestation (not legal verification)"


def test_create_without_authorization_is_allowed_but_flagged(client: TestClient) -> None:
    pid = _create(client, authorization=None)["project_id"]
    assert client.get(f"/api/projects/{pid}").json()["authorization_status"] == "missing"


@pytest.mark.parametrize(
    ("auth", "fragment"),
    [
        ({"attestation": False}, "attestation is required"),
        (
            {"window_end": (NOW - timedelta(days=5)).isoformat()},
            "window_end must be after window_start",
        ),
        ({"window_start": "2026-01-01T00:00:00"}, "timezone"),
        ({"authorized_by": ""}, "at least 1 character"),
    ],
)
def test_authorization_validation_errors_are_useful(
    client: TestClient, auth: dict[str, Any], fragment: str
) -> None:
    resp = client.post(
        "/api/projects", json={"name": "x", "client_name": "y", "authorization": _auth(**auth)}
    )
    assert resp.status_code == 422
    body = resp.json()["error"]
    assert body["code"] == "validation_failed"
    text = " ".join(d["message"] for d in body["details"]).lower()
    assert fragment.lower() in text
    assert all(d["loc"] for d in body["details"])  # every message points at a field


def test_unknown_fields_rejected(client: TestClient) -> None:
    resp = client.post("/api/projects", json={"name": "x", "client_name": "y", "is_admin": True})
    assert resp.status_code == 422
    assert resp.json()["error"]["details"][0]["loc"][-1] == "is_admin"


def test_update_with_revision_and_audit(client: TestClient, repo: StorageRepository) -> None:
    project = _create(client)
    pid = project["project_id"]
    resp = client.patch(
        f"/api/projects/{pid}",
        json={"expected_revision": 1, "name": "Renamed", "scope": {"hosts": ["api.example.com"]}},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "Renamed" and resp.json()["revision"] == 2
    stale = client.patch(
        f"/api/projects/{pid}", json={"expected_revision": 1, "name": "Lost update"}
    )
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "revision_conflict"
    archived = client.patch(
        f"/api/projects/{pid}", json={"expected_revision": 2, "status": "archived"}
    )
    assert archived.json()["status"] == "archived"
    actions = [e.action for e in repo.audit.list(project_id=pid).items]
    assert actions[:4] == [
        "project_updated",
        "project_archived",
        "project_updated",
        "scope_changed",
    ]
    empty = client.patch(f"/api/projects/{pid}", json={"expected_revision": 3})
    assert empty.status_code == 422


def test_reauthorization_creates_new_attestation(client: TestClient) -> None:
    project = _create(client)
    pid = project["project_id"]
    resp = client.patch(
        f"/api/projects/{pid}",
        json={"expected_revision": 1, "authorization": _auth(reference="SOW-2")},
    )
    new_auth = resp.json()["authorization"]
    assert new_auth["reference"] == "SOW-2"
    assert new_auth["attestation_event_id"] != project["authorization"]["attestation_event_id"]


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (NOW + timedelta(days=2), NOW + timedelta(days=9), "not_started"),
        (NOW - timedelta(days=9), NOW - timedelta(days=1), "expired"),
        (NOW - timedelta(days=1), NOW + timedelta(days=3), "expiring_soon"),
    ],
)
def test_authorization_status_indicator(
    client: TestClient, start: datetime, end: datetime, expected: str
) -> None:
    pid = _create(
        client, authorization=_auth(window_start=start.isoformat(), window_end=end.isoformat())
    )["project_id"]
    assert client.get(f"/api/projects/{pid}").json()["authorization_status"] == expected


def test_list_search_sort_pagination(client: TestClient) -> None:
    for name, client_name in [("Bravo", "Bank"), ("Alpha", "Retail"), ("Charlie", "Bank")]:
        _create(client, name=name, client_name=client_name)
    page = client.get("/api/projects", params={"sort": "name", "order": "asc", "limit": 2}).json()
    assert [p["project"]["name"] for p in page["items"]] == ["Alpha", "Bravo"] and page[
        "total"
    ] == 3
    page2 = client.get(
        "/api/projects", params={"sort": "name", "order": "asc", "limit": 2, "offset": 2}
    ).json()
    assert [p["project"]["name"] for p in page2["items"]] == ["Charlie"]
    bank = client.get("/api/projects", params={"q": "bank"}).json()
    assert {p["project"]["name"] for p in bank["items"]} == {"Bravo", "Charlie"}
    assert client.get("/api/projects", params={"limit": 500}).status_code == 422
    assert client.get("/api/projects", params={"sort": "__class__"}).status_code == 422


# ------------------------------------------------------------------ delete


def test_delete_requires_exact_confirmation_and_reports_impact(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _create(client, name="Delete me")["project_id"]
    repo.create_finding(make_finding(pid))
    repo.create_asset(make_asset(pid))
    impact = client.get(f"/api/projects/{pid}/deletion-impact").json()
    assert impact["counts"]["finding"] == 1 and impact["counts"]["asset"] == 1
    assert impact["confirm_with"] == "Delete me"
    wrong = client.delete(f"/api/projects/{pid}", params={"confirm": "delete me"})
    assert wrong.status_code == 422 and "nothing was deleted" in wrong.json()["error"]["message"]
    assert client.get(f"/api/projects/{pid}").status_code == 200
    ok = client.delete(f"/api/projects/{pid}", params={"confirm": "Delete me"})
    assert ok.status_code == 200
    assert client.get(f"/api/projects/{pid}").status_code == 404
    deleted = repo.audit.list(project_id=pid, action="project_deleted").items  # type: ignore[arg-type]
    assert deleted and deleted[0].metadata["removed"]["finding"] == 1


@pytest.mark.parametrize(
    "bad",
    [
        "..%2F..%2Fetc",
        "%2e%2e",
        "prj_123",
        "PRJ_" + "a" * 32,
        "fnd_" + "a" * 32,
        "prj_" + "a" * 32 + "%00",
    ],
)
def test_project_routes_reject_malformed_ids(client: TestClient, bad: str) -> None:
    for method, path in [
        ("GET", f"/api/projects/{bad}"),
        ("PATCH", f"/api/projects/{bad}"),
        ("GET", f"/api/projects/{bad}/deletion-impact"),
        ("DELETE", f"/api/projects/{bad}?confirm=x"),
    ]:
        kwargs = {"json": {"expected_revision": 1, "name": "x"}} if method == "PATCH" else {}
        resp = client.request(method, path, **kwargs)
        assert resp.status_code in (400, 404), (method, path, resp.status_code)
        assert resp.json()["error"]["code"] in ("invalid_id", "not_found")
    for path in ("/api/findings", "/api/assets", "/api/scans", "/api/dashboard/summary"):
        resp = client.get(path, params={"project_id": "../../etc"})
        assert resp.status_code == 400 and resp.json()["error"]["code"] == "invalid_id"


def test_unknown_project_is_404(client: TestClient) -> None:
    resp = client.get(f"/api/projects/{new_id('project')}")
    assert resp.status_code == 404 and resp.json()["error"]["code"] == "not_found"


# ------------------------------------------------------------------ scope preview


def _preview(client: TestClient, **body: Any) -> dict[str, Any]:
    resp = client.post("/api/scope/preview", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()  # type: ignore[no-any-return]


def test_scope_preview_normalizes_and_classifies(client: TestClient) -> None:
    out = _preview(
        client,
        targets=[
            "App.Example.COM.",
            "*.Example.org",
            "https://shop.example.net:8443/store/",
            "203.0.113.0/24",
            "bücher.example",
            "# comment",
            "",
        ],
        exclude_targets=["admin.example.com"],
        exclude_paths=["/logout"],
        ports=["443", "8443"],
    )
    assert out["valid"] and out["error_count"] == 0
    scope = out["scope"]
    assert scope["hosts"] == ["app.example.com", "shop.example.net", "xn--bcher-kva.example"]
    assert scope["wildcard_domains"] == ["*.example.org"]
    assert scope["ip_ranges"] == ["203.0.113.0/24"]
    assert scope["ports"] == [443, 8443] and "/store/" in scope["path_prefixes"]
    assert scope["exclusions"]["hosts"] == ["admin.example.com"]
    assert scope["exclusions"]["path_prefixes"] == ["/logout"]
    assert "admin.example.com" not in scope["hosts"]
    assert any("Phase 03" in n for n in out["notes"])


@pytest.mark.parametrize(
    ("target", "fragment"),
    [
        ("https://user:pass@example.com/", "credentials"),
        ("ftp://example.com", "only http and https"),
        ("javascript:alert(1)", "not a valid hostname"),
        ("exa mple.com", "not a valid hostname"),
        ("-bad.example.com", "not a valid hostname"),
        ("a" * 300 + ".com", "not a valid hostname"),
    ],
)
def test_scope_preview_rejects_bad_targets(client: TestClient, target: str, fragment: str) -> None:
    out = _preview(client, targets=[target, "ok.example.com"])
    assert not out["valid"] and out["scope"] is None
    errors = [e["error"] for e in out["entries"] if e["error"]]
    assert any(fragment in e for e in errors), errors


def test_scope_preview_warns_on_private_ranges_and_requires_a_target(client: TestClient) -> None:
    out = _preview(client, targets=["10.0.0.0/8", "127.0.0.1"])
    warnings = [w for e in out["entries"] for w in e["warnings"]]
    assert any("Blocked by default" in w for w in warnings)
    assert any("override" in n for n in out["notes"])
    empty = _preview(client, targets=[])
    assert not empty["valid"] and "At least one in-scope" in empty["entries"][-1]["error"]


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("ports", "0", "between 1 and 65535"),
        ("ports", "http", "between 1 and 65535"),
        ("path_prefixes", "/a/../b", "dot segments"),
        ("path_prefixes", "/%2e%2e/", "dot segments"),
        ("path_prefixes", "admin", "must start with '/'"),
    ],
)
def test_scope_preview_rejects_bad_ports_and_paths(
    client: TestClient, field: str, value: str, fragment: str
) -> None:
    out = _preview(client, targets=["ok.example.com"], **{field: [value]})
    assert not out["valid"]
    assert any(fragment in (e["error"] or "") for e in out["entries"])


def test_scope_preview_bounds(client: TestClient) -> None:
    resp = client.post("/api/scope/preview", json={"targets": ["x.example.com"] * 1001})
    assert resp.status_code == 422


# ------------------------------------------------------------------ dashboard and drill-down


def test_dashboard_is_honest_zero_when_empty(client: TestClient) -> None:
    body = client.get("/api/dashboard/summary").json()
    assert body["projects"]["total"] == 0
    assert body["scans"] == {
        "total": 0,
        "active": 0,
        "failed": 0,
        "by_state": body["scans"]["by_state"],
        "last_scan_at": None,
        "last_scan_state": None,
    }
    assert set(body["scans"]["by_state"].values()) == {0}
    assert body["findings"]["total"] == 0 and set(body["findings"]["by_severity"].values()) == {0}
    assert body["assets"]["total"] == 0
    assert [e["action"] for e in body["recent_activity"]] == ["storage_initialized"]


def test_dashboard_counts_derive_from_stored_records(
    client: TestClient, repo: StorageRepository
) -> None:
    a = _create(client, name="A")["project_id"]
    b = _create(client, name="B", authorization=None)["project_id"]
    for sev, status in [("critical", "new"), ("high", "confirmed"), ("high", "false_positive")]:
        repo.create_finding(make_finding(a, severity=sev, analyst_status=status))
    repo.create_finding(make_finding(b, severity="low", confidence="potential"))
    repo.create_asset(make_asset(a))
    repo.create_scan(
        ScanJob(scan_id=new_id("scan"), project_id=a, module="web_app", state="failed")
    )
    repo.create_scan(
        ScanJob(scan_id=new_id("scan"), project_id=b, module="web_app", state="running")
    )
    body = client.get("/api/dashboard/summary").json()
    assert body["projects"]["total"] == 2
    assert (
        body["projects"]["authorization"]["missing"] == 1
        and body["projects"]["authorization"]["active"] == 1
    )
    assert body["findings"]["total"] == 4 and body["findings"]["open"] == 3
    assert (
        body["findings"]["by_severity"]["high"] == 2
        and body["findings"]["by_severity"]["critical"] == 1
    )
    assert body["findings"]["by_confidence"]["potential"] == 1
    assert (
        body["scans"]["total"] == 2
        and body["scans"]["active"] == 1
        and body["scans"]["failed"] == 1
    )
    assert body["assets"]["total"] == 1
    scoped = client.get("/api/dashboard/summary", params={"project_id": b}).json()
    assert scoped["findings"]["total"] == 1 and scoped["projects"]["total"] == 1
    # KPI drill-down lists reconcile with the counters
    high = client.get("/api/findings", params={"severity": "high"}).json()
    assert high["total"] == body["findings"]["by_severity"]["high"]
    failed = client.get("/api/scans", params={"state": "failed"}).json()
    assert failed["total"] == body["scans"]["failed"]
    assert client.get("/api/assets").json()["total"] == body["assets"]["total"]
    assert client.get("/api/findings", params={"severity": "bogus"}).status_code == 422


def test_audit_endpoint_lists_newest_first(client: TestClient) -> None:
    pid = _create(client)["project_id"]
    page = client.get("/api/audit", params={"project_id": pid}).json()
    assert [e["action"] for e in page["items"]] == ["project_created", "authorization_attested"]


# ------------------------------------------------------------------ security headers and UI serving


def test_security_headers_present(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


def test_spa_serving_with_deep_links_and_no_traversal(
    tmp_path: Path, settings: RuntimeSettings, repo: StorageRepository
) -> None:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    (dist / "favicon.svg").write_text("<svg/>")
    (tmp_path / "secret.txt").write_text("top secret")
    app = create_app(settings, repository=repo)
    assert mount_ui(app, dist)
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as c:
        assert "id=root" in c.get("/").text
        assert "id=root" in c.get("/projects/prj_123/edit").text  # client route survives reload
        assert c.get("/assets/app.js").text == "console.log(1)"
        assert c.get("/favicon.svg").text == "<svg/>"
        for evil in (
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/assets/../../secret.txt",
            "/..%5csecret.txt",
        ):
            assert "top secret" not in c.get(evil).text, evil
        api = c.get("/api/does-not-exist")
        assert api.status_code == 404 and api.json()["error"]["code"] == "not_found"
