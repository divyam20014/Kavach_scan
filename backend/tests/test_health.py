import tomllib
from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Route

from app import __version__
from app.main import create_app
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT

SYSTEM_ROUTES = {
    "/api/health",
    "/api/version",
    "/api/readiness",
    "/api/diagnostics/storage",
    "/api/diagnostics/integrity-check",
    "/api/diagnostics/support-bundle",
    # Phase 02
    "/api/projects",
    "/api/projects/{project_id}",
    "/api/projects/{project_id}/deletion-impact",
    "/api/scope/preview",
    "/api/dashboard/summary",
    "/api/findings",
    "/api/assets",
    "/api/scans",
    "/api/audit",
    # Phase 03
    "/api/scope/blocked-ranges",
    "/api/projects/{project_id}/scope/policy",
    "/api/projects/{project_id}/scope/check",
    "/api/projects/{project_id}/scope/classify-host",
    "/api/projects/{project_id}/internal-override",
    # Phase 04
    "/api/jobs/modules",
    "/api/jobs/status",
    "/api/kill-switch",
    "/api/projects/{project_id}/scans",
    "/api/projects/{project_id}/scans/{scan_id}",
    "/api/projects/{project_id}/scans/{scan_id}/events",
    "/api/projects/{project_id}/scans/{scan_id}/console",
    "/api/projects/{project_id}/scans/{scan_id}/cancel",
    "/api/projects/{project_id}/scans/{scan_id}/retry",
    # Phase 05
    "/api/projects/{project_id}/web-scan-profile",
    "/api/projects/{project_id}/scans/{scan_id}/results/{kind}",
    # Phase 06
    "/api/projects/{project_id}/surface-scan-profile",
    "/api/projects/{project_id}/surface",
    "/api/projects/{project_id}/assets/{asset_id}",
    "/api/projects/{project_id}/assets/{asset_id}/approve",
    # Phase 07
    "/api/projects/{project_id}/api-specs",
    "/api/projects/{project_id}/api-specs/{import_id}",
    "/api/projects/{project_id}/api-specs/{import_id}/validate",
    "/api/projects/{project_id}/api-security-plan",
    # Phase 08
    "/api/projects/{project_id}/imports",
    "/api/projects/{project_id}/imports/{import_id}",
    "/api/projects/{project_id}/imports/{import_id}/commit",
    "/api/imports/formats",
    # Phase 09
    "/api/projects/{project_id}/findings/{finding_id}",
    "/api/projects/{project_id}/findings/{finding_id}/comments",
    "/api/projects/{project_id}/findings/{finding_id}/merge",
    "/api/projects/{project_id}/findings/{finding_id}/unmerge",
    "/api/standards/catalogs",
    "/api/risk-formula",
    # Phase 10
    "/api/projects/{project_id}/reports",
    "/api/projects/{project_id}/reports/preview",
    "/api/projects/{project_id}/reports/{report_id}",
    "/api/projects/{project_id}/reports/{report_id}/download/{fmt}",
    "/api/projects/{project_id}/export/findings.json",
    "/api/projects/{project_id}/export/findings.csv",
    "/api/projects/{project_id}/export/assets.json",
    "/api/projects/{project_id}/export/assets.csv",
    "/api/projects/{project_id}/backup/export",
    "/api/backup/preview",
    "/api/backup/restore",
    # Phase 11
    "/api/settings",
    "/api/integrations",
    "/api/integrations/{tool_id}/selftest",
    "/api/cve-catalog",
    "/api/cve-catalog/import",
    # Roadmap Phase 2 (TBD-087)
    "/api/integrations/trivy/db-status",
    "/api/integrations/trivy/download-db",
}

# No lifespan: these endpoints must work without storage.
bare = TestClient(create_app(), base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT)


def test_health_ok_without_storage() -> None:
    resp = bare.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_version_reports_no_scanning() -> None:
    body = bare.get("/api/version").json()
    assert body["version"] == __version__
    assert body["api_version"] == "1"
    assert body["storage_version"] == 1
    assert body["scanning_available"] is False


def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    assert tomllib.loads(pyproject.read_text("utf-8"))["project"]["version"] == __version__


def test_only_known_routes_exist() -> None:
    """Guard: routes for later phases (scan start, imports, reports...) must not appear early."""
    app = create_app()
    assert set(app.openapi()["paths"]) == SYSTEM_ROUTES
    top_level = {r.path for r in app.routes if isinstance(r, Route | APIRoute)}
    assert top_level <= {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def test_storage_endpoints_unavailable_without_storage() -> None:
    resp = bare.get("/api/readiness")
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "service_unavailable"


def test_health_endpoints_reject_writes() -> None:
    resp = bare.post("/api/health")
    assert resp.status_code == 405
    assert resp.json()["error"]["code"] == "method_not_allowed"


SCAN_WRITE_ROUTES = {
    ("/api/projects/{project_id}/scans", "post"),
    ("/api/projects/{project_id}/scans/{scan_id}/cancel", "post"),
    ("/api/projects/{project_id}/scans/{scan_id}/retry", "post"),
}


def test_scans_can_only_be_started_through_the_gated_job_routes() -> None:
    paths = create_app().openapi()["paths"]
    for path, ops in paths.items():
        if "scan" in path:
            writes = {(path, op) for op in ops if op != "get"}
            assert writes <= SCAN_WRITE_ROUTES, (
                f"unexpected scan write route(s): {writes - SCAN_WRITE_ROUTES}"
            )
    start = paths["/api/projects/{project_id}/scans"]["post"]
    schema = start["requestBody"]["content"]["application/json"]["schema"]
    assert schema["$ref"].endswith("StartScanRequest")


def test_unknown_routes_are_404_not_fake_200() -> None:
    for method, path in [
        ("POST", "/api/projects/x/notifications"),
        ("POST", "/api/reports"),
        ("GET", "/api/integrations/unknown-tool/history"),
    ]:
        resp = bare.request(method, path)
        assert resp.status_code == 404, (method, path)
        assert resp.json()["error"]["code"] == "not_found"
    assert bare.post("/api/scans").status_code == 405  # list exists; nothing can create a scan
