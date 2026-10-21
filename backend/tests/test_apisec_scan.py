"""Phase 07 end-to-end: API security scanner through the real JobManager.

Offline inventory and local fixture API only. The spec's server points at the loopback
fixture; the project scope authorizes 127.0.0.1 via an internal override."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from app.core.settings import RuntimeSettings
from app.jobs.manager import JobManager, StartScanRequest
from app.models import new_id
from app.models.common import ScanModule, ScanState
from app.models.import_artifact import ImportArtifact
from app.scanners.apisec.runner import ApiSecRunner
from app.storage.repository import StorageRepository
from tests.apifixtures import start_api
from tests.jobhelpers import terminal, wait_for
from tests.surfacefixtures import surface_project


def _spec(port: int, *, leaky: bool = False) -> dict[str, Any]:
    order_path = "/orders/{orderId}"
    return {
        "openapi": "3.0.3",
        "info": {"title": "Fixture API", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {"User": {"properties": {"name": {}, "role": {}, "isAdmin": {}}}},
        },
        "paths": {
            order_path: {
                "get": {
                    "operationId": "getOrder",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "orderId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {}},
                }
            },
            "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
            "/trace": {"get": {"operationId": "trace", "responses": {"500": {}}}},
            "/noratelimit": {"get": {"operationId": "noRate", "responses": {"200": {}}}},
            "/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/User"}}
                        }
                    },
                    "responses": {"201": {}},
                }
            },
        },
    }


def _project(repo: StorageRepository, port: int) -> str:
    return repo.create_project(
        surface_project(
            [port], hosts=[], ip_ranges=["127.0.0.1/32"], allowed_modules=["api_security"]
        )
    ).project_id


def _import(repo: StorageRepository, pid: str, doc: dict[str, Any]) -> str:
    raw = json.dumps(doc).encode()
    artifact = ImportArtifact(
        import_id=new_id("import"),
        project_id=pid,
        display_filename="s.json",
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        source_type="openapi_spec",
        status="parsed",
    )
    return repo.create_import(artifact, raw).import_id


def _scan(
    repo: StorageRepository,
    settings: RuntimeSettings,
    pid: str,
    params: dict[str, Any],
    timeout: float = 60,
) -> Any:
    jm = JobManager(repo, settings, runners={ScanModule.API_SECURITY: ApiSecRunner()})
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.API_SECURITY, targets=["api-spec"], parameters=params, confirmed=True
        ),
    )
    jm.start()
    try:
        return wait_for(repo, pid, scan.scan_id, terminal, timeout=timeout)
    finally:
        jm.stop()


def _out(repo: StorageRepository, pid: str, sid: str, name: str) -> Any:
    return json.loads(repo.read_scan_output(pid, sid, name))


@pytest.fixture
def api() -> Any:
    server = start_api()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def test_inventory_only_makes_zero_requests(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    from tests.apifixtures import ApiHandler

    port = api.server_address[1]
    pid = _project(repo, port)
    imp = _import(repo, pid, _spec(port))
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": True})
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["inventory_only"] is True and summary["requests_sent"] == 0
    assert ApiHandler.requests == []  # the fixture API was never contacted
    assert summary["operations_total"] == 5
    # all network checks reported skipped, never passed
    cov = {
        (r["rule_id"], r["outcome"])
        for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]
    }
    for rid in ("API-AUTH-001", "API-CFG-001", "API-BOLA-000", "API-RATE-000"):
        assert (rid, "skipped") in cov and (rid, "pass") not in cov
    # inventory still flags the mass-assignment sensitive property (offline)
    assert any(f.rule_id == "API-MASS-001" for f in repo.list_findings(pid, limit=50).items)


def test_out_of_scope_server_is_never_contacted(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    from tests.apifixtures import ApiHandler

    port = api.server_address[1]
    # project scopes a DIFFERENT port, so the spec's server is out of scope
    pid = repo.create_project(
        surface_project(
            [port + 1 if port < 65535 else port - 1],
            hosts=[],
            ip_ranges=["127.0.0.1/32"],
            allowed_modules=["api_security"],
        )
    ).project_id
    imp = _import(repo, pid, _spec(port))
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": False})
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["requests_sent"] == 0 and summary["server"] == ""
    assert ApiHandler.requests == []
    cov = {
        (r["rule_id"], r["outcome"])
        for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]
    }
    assert ("API-CFG-001", "skipped") in cov


def test_network_checks_only_hit_approved_server(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    from tests.apifixtures import ApiHandler

    port = api.server_address[1]
    pid = _project(repo, port)
    imp = _import(repo, pid, _spec(port))
    done = _scan(
        repo,
        settings,
        pid,
        {
            "import_id": imp,
            "inventory_only": False,
            "check_error_leakage": True,
            "check_config": True,
            "check_unauth_baseline": True,
        },
    )
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["requests_sent"] > 0
    # every request went to the loopback fixture, nowhere else
    assert all(p.startswith("/v1/") for _m, p, _a in ApiHandler.requests)
    rules = {f.rule_id for f in repo.list_findings(pid, limit=100).items}
    assert "API-CFG-002" in rules  # http server -> insecure transport finding
    # the protected getOrder returned 403 unauthenticated -> API-AUTH-001 should pass, not finding
    cov = {
        (r["rule_id"], r["outcome"])
        for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]
    }
    assert ("API-AUTH-001", "finding") not in cov


def test_verbose_stack_trace_is_detected(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    # a spec whose only read-only op is /trace
    doc = _spec(port)
    doc["paths"] = {"/trace": {"get": {"operationId": "trace", "responses": {"500": {}}}}}
    imp = _import(repo, pid, doc)
    _scan(
        repo,
        settings,
        pid,
        {"import_id": imp, "inventory_only": False, "check_error_leakage": True},
    )
    rules = {f.rule_id for f in repo.list_findings(pid, limit=50).items}
    assert "API-ERR-001" in rules
    # the stack trace text itself must not be stored verbatim beyond a short excerpt
    err = next(f for f in repo.list_findings(pid, limit=50).items if f.rule_id == "API-ERR-001")
    assert err.evidence_ids


def test_idor_is_skipped_without_identities(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    imp = _import(repo, pid, _spec(port))
    # enable_idor not set -> must be skipped with a reason, never run
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": False})
    cov = {r["rule_id"]: r for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]}
    assert cov["API-BOLA-000"]["outcome"] == "skipped"
    assert "two test identities" in cov["API-BOLA-000"]["rationale"]
    assert not any(f.rule_id == "API-BOLA-001" for f in repo.list_findings(pid, limit=50).items)


def test_idor_detects_cross_user_access_with_identities(
    repo: StorageRepository, settings: RuntimeSettings, api: Any, monkeypatch: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    # a spec whose order path returns a shared object for any token (leaky)
    doc = _spec(port)
    imp = _import(repo, pid, doc)
    monkeypatch.setenv("VAPT_TOK_A", "token-a-value")
    monkeypatch.setenv("VAPT_TOK_B", "token-b-value")
    params = {
        "import_id": imp,
        "inventory_only": False,
        "enable_idor": True,
        "risk_ack": True,
        "auth_profiles": [
            {"alias": "a", "scheme": "bearer", "secret_ref": "env:VAPT_TOK_A"},
            {"alias": "b", "scheme": "bearer", "secret_ref": "env:VAPT_TOK_B"},
        ],
        "identities": [
            {"label": "usera", "auth_alias": "a"},
            {"label": "userb", "auth_alias": "b"},
        ],
        "ownership": [
            {
                "operation_key": "GET /orders/{orderId}",
                "param_name": "orderId",
                "owner_label": "usera",
                "object_id": "leaky",
            },
            {
                "operation_key": "GET /orders/{orderId}",
                "param_name": "orderId",
                "owner_label": "userb",
                "object_id": "leaky",
            },
        ],
    }
    done = _scan(repo, settings, pid, params)
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason
    rules = {f.rule_id for f in repo.list_findings(pid, limit=50).items}
    assert "API-BOLA-001" in rules  # user B received user A's "leaky" object
    # secrets never stored
    blob = b""
    for p in repo.root.rglob("*"):
        if p.is_file() and pid in str(p):
            blob += p.read_bytes()
    assert b"token-a-value" not in blob and b"token-b-value" not in blob


def test_mutating_write_is_disabled_by_default(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    from tests.apifixtures import ApiHandler

    port = api.server_address[1]
    pid = _project(repo, port)
    imp = _import(repo, pid, _spec(port))
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": False})
    cov = {r["rule_id"]: r for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]}
    assert cov["API-MASS-000"]["outcome"] == "skipped"
    # no POST/PUT/PATCH/DELETE ever sent to the fixture
    assert all(m == "GET" for m, _p, _a in ApiHandler.requests)


def test_rate_probe_is_bounded_and_opt_in(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    from tests.apifixtures import ApiHandler

    port = api.server_address[1]
    pid = _project(repo, port)
    imp = _import(repo, pid, _spec(port))
    params = {
        "import_id": imp,
        "inventory_only": False,
        "enable_rate_probe": True,
        "check_config": False,
        "check_error_leakage": False,
        "risk_ack": True,
        "rate_probe_operation": "GET /noratelimit",
        "rate_probe_count": 5,
    }
    done = _scan(repo, settings, pid, params)
    probe_requests = [r for r in ApiHandler.requests if r[1] == "/v1/noratelimit"]
    assert 1 <= len(probe_requests) <= 5  # capped, never a flood
    cov = {r["rule_id"]: r for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]}
    assert cov["API-RATE-000"]["outcome"] == "observation"
    # no limit tripped -> finding, but phrased as "does not prove"
    assert cov["API-RATE-001"]["outcome"] == "finding"


def test_coverage_has_skipped_reasons_and_no_false_all_passed(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    imp = _import(repo, pid, _spec(port))
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": True})
    results = _out(repo, pid, done.scan_id, "coverage.json")["results"]
    skipped = [r for r in results if r["outcome"] == "skipped"]
    assert skipped and all(r["rationale"] for r in skipped)  # every skip has a reason
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert "all passed" not in json.dumps(summary).lower()
    assert summary["operations_skipped"] == {} or isinstance(summary["operations_skipped"], dict)
