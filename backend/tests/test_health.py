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


def test_only_system_routes_exist() -> None:
    """Guard: no scan, project, or import routes may exist before their phases."""
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


def test_unknown_routes_are_404_not_fake_200() -> None:
    for method, path in [
        ("POST", "/api/scans"),
        ("POST", "/api/projects"),
        ("GET", "/api/projects"),
        ("POST", "/api/projects/x/imports"),
        ("GET", "/api/findings"),
    ]:
        resp = bare.request(method, path)
        assert resp.status_code == 404, (method, path)
        assert resp.json()["error"]["code"] == "not_found"
