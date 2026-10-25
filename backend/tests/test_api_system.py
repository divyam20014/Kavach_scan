import json
from pathlib import Path

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.main import create_app
from app.storage.repository import StorageRepository
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT, make_project


def test_readiness_ready_with_storage(client: TestClient) -> None:
    resp = client.get("/api/readiness")
    assert resp.status_code == 200
    body = resp.json()
    assert (
        body["status"] == "ready" and body["storage_ready"] is True and body["integrity_ok"] is True
    )


def test_storage_diagnostics_do_not_leak_absolute_home_path(client: TestClient) -> None:
    body = client.get("/api/diagnostics/storage").json()
    diag = body["storage"]
    assert diag["ready"] and diag["writable"] and diag["instance_lock"] == "held_by_this_process"
    assert diag["storage_version"] == 1
    home = str(Path.home())
    assert home not in diag["data_dir"] and diag["data_dir"].startswith("~/")
    assert body["last_integrity_check"]["issues"] == []


def test_integrity_check_endpoint_reports_and_audits(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = repo.create_project(make_project()).project_id
    repo.paths.path("projects", pid, "project.json").write_text("{broken")
    resp = client.post("/api/diagnostics/integrity-check")
    assert resp.status_code == 200
    kinds = [i["kind"] for i in resp.json()["issues"]]
    assert kinds == ["corrupt_record"]
    assert client.get("/api/readiness").json()["integrity_ok"] is False
    assert repo.audit.list().items[0].action == "integrity_checked"


def test_correlation_id_generated_echoed_and_sanitized(client: TestClient) -> None:
    generated = client.get("/api/health").headers["x-request-id"]
    assert len(generated) == 32
    assert (
        client.get("/api/health", headers={"X-Request-ID": "abc-12345678"}).headers["x-request-id"]
        == "abc-12345678"
    )
    injected = client.get("/api/health", headers={"X-Request-ID": "bad\r\nSet-Cookie: x=1"})
    assert injected.headers["x-request-id"] != "bad\r\nSet-Cookie: x=1"
    assert "set-cookie" not in injected.headers


def test_error_envelope_carries_correlation_id(client: TestClient) -> None:
    resp = client.get("/api/nope", headers={"X-Request-ID": "trace-0001"})
    assert resp.status_code == 404
    assert resp.json()["error"] == {
        "code": "not_found",
        "message": "Not Found",
        "correlation_id": "trace-0001",
        "details": [],
    }


def test_request_size_limit(settings: RuntimeSettings, repo: StorageRepository) -> None:
    small = settings.model_copy(update={"max_request_bytes": 16 * 1024})
    with TestClient(
        create_app(small, repository=repo), base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT
    ) as c:
        big = c.post("/api/diagnostics/integrity-check", content=b"x" * (17 * 1024))
        assert big.status_code == 413 and big.json()["error"]["code"] == "payload_too_large"

        def chunks():  # type: ignore[no-untyped-def]
            for _ in range(20):
                yield b"y" * 1024

        chunked = c.post("/api/diagnostics/integrity-check", content=chunks())
        assert chunked.status_code == 413


def test_upload_routes_use_their_own_larger_size_limit_not_the_json_default(
    settings: RuntimeSettings, repo: StorageRepository,
) -> None:
    """Phase 12 verification defect: the global request-size guard used one small, JSON-sized
    default for every route, including file-upload routes that each declare and enforce their
    own much larger documented cap (CVE catalog 15 MiB, imports 25 MiB, API specs 8 MiB,
    backup archives 200 MiB) deeper in their own code — making every one of those larger,
    tested, documented limits unreachable in practice. A body bigger than the tight JSON
    default, but still well inside the route's own documented cap, must reach the route."""
    import json as json_mod

    from tests.surfacefixtures import surface_project

    with TestClient(
        create_app(settings, repository=repo), base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT
    ) as c:
        pid = repo.create_project(surface_project([80], hosts=["x.test"])).project_id

        # ~2 MiB CVE catalog: over the 1 MiB JSON-sized default, well under its own 15 MiB cap.
        catalog = json_mod.dumps({
            "source": "big", "catalog_version": "1.0",
            "entries": [
                {"product": f"p{i}", "version_spec": "<1.0", "cve_id": "CVE-2020-0001",
                 "summary": "A" * 400}
                for i in range(4000)
            ],
        }).encode()
        assert len(catalog) > settings.max_request_bytes
        resp = c.post(
            "/api/cve-catalog/import", files={"file": ("big.json", catalog, "application/json")}
        )
        assert resp.status_code == 201, resp.text

        # ~2 MiB generic-JSON import: over the JSON-sized default, well under the 25 MiB cap.
        findings_doc = json_mod.dumps({
            "findings": [
                {"title": f"Finding {i}", "severity": "low", "host": "10.0.0.1"}
                for i in range(20_000)
            ]
        }).encode()
        assert len(findings_doc) > settings.max_request_bytes
        up = c.post(
            f"/api/projects/{pid}/imports",
            files={"file": ("big.json", findings_doc, "application/json")},
        )
        assert up.status_code == 201, up.text

    # An ordinary (non-upload) JSON route is unaffected: still capped at the tight default.
    with TestClient(
        create_app(settings, repository=repo), base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT
    ) as c:
        resp = c.post(
            "/api/projects",
            json={"name": "x", "client_name": "y", "notes": "A" * (settings.max_request_bytes + 1)},
        )
        assert resp.status_code == 413


def test_unhandled_errors_are_generic_and_logged_without_secrets(
    settings: RuntimeSettings, repo: StorageRepository, caplog: pytest.LogCaptureFixture
) -> None:
    app = create_app(settings, repository=repo)
    router = APIRouter()

    @router.get("/api/_boom")
    def boom() -> None:
        raise RuntimeError("db password=hunter2 leaked in exception")

    app.include_router(router)
    with TestClient(
        app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT, raise_server_exceptions=False
    ) as c:
        resp = c.get("/api/_boom")
    assert resp.status_code == 500
    body = resp.json()
    assert body["error"]["code"] == "internal_error"
    assert "hunter2" not in json.dumps(body) and "Traceback" not in resp.text


def test_validation_errors_do_not_echo_input(
    settings: RuntimeSettings, repo: StorageRepository
) -> None:
    app = create_app(settings, repository=repo)
    router = APIRouter()

    @router.get("/api/_typed")
    def typed(n: int) -> dict[str, int]:
        return {"n": n}

    app.include_router(router)
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as c:
        resp = c.get("/api/_typed", params={"n": "token=supersecretvalue"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_failed"
    assert "supersecretvalue" not in resp.text


def test_request_log_redacts_query_strings(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="app.request"):
        client.get("/api/health?access_token=tok_should_not_appear&page=2")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "tok_should_not_appear" not in text and "page=2" in text


def test_lifespan_opens_and_releases_storage(settings: RuntimeSettings) -> None:
    app = create_app(settings)
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as c:
        assert c.get("/api/readiness").status_code == 200
    with StorageRepository.open(settings):  # lock released on shutdown
        pass
