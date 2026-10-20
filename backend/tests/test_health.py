import tomllib
from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Route

from app import __version__
from app.main import create_app

client = TestClient(create_app(), client=("127.0.0.1", 50000))


def test_health_ok() -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_version_reports_no_scanning() -> None:
    resp = client.get("/api/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == __version__
    assert body["scanning_available"] is False


def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    assert tomllib.loads(pyproject.read_text("utf-8"))["project"]["version"] == __version__


def test_only_system_routes_exist() -> None:
    """Phase 00 guard: no scan, project, or import routes may exist yet."""
    app = create_app()
    assert set(app.openapi()["paths"]) == {"/api/health", "/api/version"}
    # Included routers are nested, so top-level plain routes are only FastAPI's docs pages.
    top_level = {r.path for r in app.routes if isinstance(r, Route | APIRoute)}
    assert top_level <= {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def test_health_endpoints_reject_writes() -> None:
    assert client.post("/api/health").status_code == 405
    assert client.delete("/api/version").status_code == 405


def test_unknown_routes_are_404_not_fake_200() -> None:
    for method, path in [
        ("POST", "/api/scans"),
        ("POST", "/api/projects"),
        ("GET", "/api/projects"),
        ("POST", "/api/projects/x/imports"),
        ("GET", "/api/findings"),
    ]:
        assert client.request(method, path).status_code == 404, (method, path)
