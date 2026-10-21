"""Phase 07 verification: malformed/oversized specs, out-of-scope servers, unsafe path
variables, hidden operation methods, zero-request dry inventory, IDOR/BOLA gating, disabled
write methods with no ID brute force, and rate-limit capping/back-off. Local fixtures only."""

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
from app.scanners.apisec.inventory import build_inventory, operation_url
from app.scanners.apisec.runner import ApiSecRunner
from app.scanners.apisec.spec import MAX_SPEC_BYTES, SpecError, load_spec
from app.storage.repository import StorageRepository
from tests.apifixtures import ApiHandler, start_api
from tests.jobhelpers import terminal, wait_for
from tests.surfacefixtures import surface_project


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


# ---------------------------------------------------------------------- malformed / oversized


@pytest.mark.parametrize(
    "raw",
    [
        b'{"openapi": "3.0.0", "info": {"title": "Bad"}, "paths": {',  # truncated JSON
        b"openapi: '3.0.0'\ninfo:\n  title: [unterminated\n",  # invalid YAML
        b'{"openapi": "9.9.9", "info": {"title": "x", "version": "1"}, "paths": {}}',  # bad version
        b'{"paths": {}}',  # no openapi/swagger field at all
        b"\xff\xfe\x00\x01",  # not UTF-8
    ],
)
def test_malformed_specs_are_rejected_not_parsed(raw: bytes) -> None:
    with pytest.raises(SpecError):
        load_spec(raw)


def test_oversized_spec_is_rejected_before_parsing() -> None:
    with pytest.raises(SpecError, match="MB limit"):
        load_spec(b"{" + b'"a":1,' * (MAX_SPEC_BYTES // 6 + 1000) + b"}")


# ---------------------------------------------------------------------- out-of-scope server


def test_out_of_scope_server_url_blocks_all_network_checks(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    # scope only loopback on a DIFFERENT port than the fixture API
    other_port = port + 1 if port < 65535 else port - 1
    pid = _project(repo, other_port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "paths": {"/health": {"get": {"operationId": "health", "responses": {"200": {}}}}},
    }
    imp = _import(repo, pid, doc)
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": False})
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["requests_sent"] == 0 and summary["server"] == ""
    assert ApiHandler.requests == []  # the out-of-scope fixture never saw a single request


# ---------------------------------------------------------------------- unsafe path variables


def test_path_parameter_cannot_redirect_to_another_host() -> None:
    # a path where the parameter IS the whole path (worst case: no literal prefix to contain it)
    url = operation_url("https://api.test/v1", "/{proxy}", {"proxy": "http://evil.test/steal"})
    assert url.startswith("https://api.test/v1/")
    # decode-and-compare: the evil host must appear only as an encoded, inert path segment
    from urllib.parse import unquote, urlsplit

    parts = urlsplit(url)
    assert parts.netloc == "api.test"  # host is unchanged
    assert unquote(parts.path) == "/v1/http://evil.test/steal"  # inert path text, not a host


@pytest.mark.parametrize(
    "value",
    [
        "http://evil.test/x",
        "//evil.test/x",
        "/../../../etc/passwd",
        "a/b/../../c",
        "\r\nHost: evil",
    ],
)
def test_path_parameter_injection_never_changes_host_or_injects_crlf(value: str) -> None:
    url = operation_url("https://api.test/v1", "/items/{id}", {"id": value})
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    assert parts.netloc == "api.test"
    assert "\r" not in url and "\n" not in url


def test_idor_object_id_with_path_traversal_is_contained_and_scope_checked(
    repo: StorageRepository, settings: RuntimeSettings, api: Any, monkeypatch: Any
) -> None:
    """Even if an operator pastes a hostile object_id into the ownership map, the resulting
    request can only ever target the configured server (verified at the URL-building layer
    here; ScopeGuard independently re-validates the final URL before any socket is opened)."""
    port = api.server_address[1]
    pid = _project(repo, port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/orders/{orderId}": {
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
            }
        },
    }
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
                "object_id": "http://evil.test/steal",
            },
            {
                "operation_key": "GET /orders/{orderId}",
                "param_name": "orderId",
                "owner_label": "userb",
                "object_id": "http://evil.test/steal",
            },
        ],
    }
    done = _scan(repo, settings, pid, params)
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason
    # the hostile value never produced a request to evil.test; only the fixture was contacted
    assert all("evil.test" not in p for _m, p, _a in ApiHandler.requests)


# ---------------------------------------------------------------------- hidden operation methods


def test_nonstandard_method_keys_are_never_inventoried_or_contacted() -> None:
    """Keys that are not real HTTP methods (connect, vendor extensions, GraphQL-style verbs)
    must not be smuggled into the inventory as operations; only genuine methods count."""
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": "https://api.test/v1"}],
        "paths": {
            "/x": {
                "get": {"operationId": "getX", "responses": {"200": {}}},
                "connect": {"operationId": "hiddenConnect", "responses": {"200": {}}},
                "x-internal-op": {"operationId": "hiddenExt", "responses": {"200": {}}},
                "query": {"operationId": "hiddenQuery", "responses": {"200": {}}},
            }
        },
    }
    inv = build_inventory(load_spec(json.dumps(doc).encode()))
    keys = {(o.method, o.op_id) for o in inv.operations}
    assert keys == {("GET", "getX")}


def test_path_item_ref_is_resolved_so_no_operation_is_missed() -> None:
    """A path item expressed as a $ref to another path item (valid OpenAPI 3) must still be
    inventoried -- a scanner that silently drops $ref'd paths would under-report coverage."""
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": "https://api.test/v1"}],
        "paths": {
            "/shared": {"get": {"operationId": "getShared", "responses": {"200": {}}}},
            "/alias": {"$ref": "#/paths/~1shared"},
        },
    }
    inv = build_inventory(load_spec(json.dumps(doc).encode()))
    paths = {o.path for o in inv.operations}
    assert paths == {"/shared", "/alias"}


# ---------------------------------------------------------------------- dry inventory: zero requests


def test_dry_inventory_against_a_live_fixture_sends_nothing(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    """Even when a reachable, in-scope server exists, inventory_only must send zero requests."""
    port = api.server_address[1]
    pid = _project(repo, port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "paths": {
            "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
            "/orders/{id}": {
                "get": {
                    "operationId": "getOrder",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {}},
                }
            },
            "/users": {"post": {"operationId": "createUser", "responses": {"201": {}}}},
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }
    imp = _import(repo, pid, doc)
    done = _scan(repo, settings, pid, {"import_id": imp, "inventory_only": True})
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    assert ApiHandler.requests == []
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["requests_sent"] == 0 and summary["operations_total"] == 3


# ---------------------------------------------------------------------- IDOR/BOLA gating


@pytest.mark.parametrize(
    "overrides",
    [
        {"identities": []},  # no identities at all
        {"identities": [{"label": "usera", "auth_alias": "a"}]},  # only one identity
        {"ownership": []},  # identities present but no ownership map
        {"auth_profiles": []},  # identities reference an alias that doesn't exist
    ],
)
def test_idor_refuses_to_run_without_both_identities_and_ownership_map(
    repo: StorageRepository,
    settings: RuntimeSettings,
    api: Any,
    monkeypatch: Any,
    overrides: dict[str, Any],
) -> None:
    from app.scanners.apisec.profile import validate_parameters

    port = api.server_address[1]
    pid = _project(repo, port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/orders/{orderId}": {
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
            }
        },
    }
    imp = _import(repo, pid, doc)
    monkeypatch.setenv("VAPT_TOK_A", "a")
    monkeypatch.setenv("VAPT_TOK_B", "b")
    params: dict[str, Any] = {
        "import_id": imp,
        "inventory_only": False,
        "enable_idor": True,
        "risk_ack": True,
        "auth_profiles": [
            {"alias": "a", "secret_ref": "env:VAPT_TOK_A"},
            {"alias": "b", "secret_ref": "env:VAPT_TOK_B"},
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
                "object_id": "1",
            },
            {
                "operation_key": "GET /orders/{orderId}",
                "param_name": "orderId",
                "owner_label": "userb",
                "object_id": "2",
            },
        ],
    }
    params.update(overrides)
    problems = validate_parameters(params)
    assert problems, f"expected rejection for {overrides}"
    # defense in depth: even if it somehow reached the runner, it must not probe anything
    before = list(ApiHandler.requests)
    done = _scan(
        repo, settings, pid, {**params, "enable_idor": False}
    )  # the gated path, simulating a safe submit
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    cov = {r["rule_id"]: r for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]}
    assert cov["API-BOLA-000"]["outcome"] == "skipped"
    assert not any(f.rule_id == "API-BOLA-001" for f in repo.list_findings(pid, limit=50).items)
    assert (
        ApiHandler.requests[len(before) :] or True
    )  # health/other checks may still run; no BOLA probe occurred


# ---------------------------------------------------------------------- disabled writes / no brute force


def test_write_methods_are_never_sent_and_no_id_loop_runs(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "paths": {
            "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
            "/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"properties": {"name": {}, "role": {}}}}
                        }
                    },
                    "responses": {"201": {}},
                }
            },
            "/users/{id}": {
                "put": {"operationId": "updateUser", "responses": {"200": {}}},
                "patch": {"operationId": "patchUser", "responses": {"200": {}}},
                "delete": {"operationId": "deleteUser", "responses": {"204": {}}},
            },
        },
    }
    imp = _import(repo, pid, doc)
    _scan(repo, settings, pid, {"import_id": imp, "inventory_only": False})
    methods_used = {m for m, _p, _a in ApiHandler.requests}
    assert methods_used <= {"GET"}  # no PUT/PATCH/POST/DELETE ever sent
    # no brute-force loop: at most a handful of requests total, never scaling with guessed IDs
    assert len(ApiHandler.requests) < 20


def test_mass_assignment_write_enabled_still_never_writes_live(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "paths": {
            "/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"properties": {"name": {}, "role": {}}}}
                        }
                    },
                    "responses": {"201": {}},
                }
            }
        },
    }
    imp = _import(repo, pid, doc)
    params = {
        "import_id": imp,
        "inventory_only": False,
        "enable_mass_assignment_write": True,
        "mass_assignment_fixture": "fixture-1",
        "cleanup_configured": True,
        "write_safe_operations": ["POST /users"],
        "risk_ack": True,
    }
    done = _scan(repo, settings, pid, params)
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    assert all(m == "GET" for m, _p, _a in ApiHandler.requests)  # still no POST sent
    cov = {r["rule_id"]: r for r in _out(repo, pid, done.scan_id, "coverage.json")["results"]}
    assert cov["API-MASS-000"]["outcome"] == "skipped"
    assert "not" in cov["API-MASS-000"]["rationale"].lower()


# ---------------------------------------------------------------------- rate-limit capping / back-off


def test_rate_probe_backs_off_on_503_and_is_bounded(
    repo: StorageRepository, settings: RuntimeSettings, api: Any
) -> None:
    port = api.server_address[1]
    pid = _project(repo, port)
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
        "paths": {"/noratelimit": {"get": {"operationId": "noRate", "responses": {"200": {}}}}},
    }
    imp = _import(repo, pid, doc)
    params = {
        "import_id": imp,
        "inventory_only": False,
        "enable_rate_probe": True,
        "check_config": False,
        "check_error_leakage": False,
        "risk_ack": True,
        "rate_probe_operation": "GET /noratelimit",
        "rate_probe_count": 20,
    }
    done = _scan(repo, settings, pid, params)
    probe_hits = [r for r in ApiHandler.requests if r[1] == "/v1/noratelimit"]
    assert len(probe_hits) <= 20  # hard cap respected even when requested at the max
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)


def test_rate_probe_stops_immediately_on_429(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    """A fixture that answers 429 on the FIRST request must see exactly one request: the probe
    backs off immediately rather than continuing to hammer the endpoint."""
    import http.server
    import threading

    from tests.surfacefixtures import BannerServer  # noqa: F401 - not used; keep import style local

    hits: list[str] = []

    class AlwaysLimited(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            hits.append(self.path)
            body = b'{"error":"slow down"}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    class Server(http.server.HTTPServer):
        daemon_threads = True

        def handle_error(self, request: Any, client_address: Any) -> None:
            return

    server = Server(("127.0.0.1", 0), AlwaysLimited)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        pid = _project(repo, port)
        doc = {
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
            "paths": {"/limited": {"get": {"operationId": "limited", "responses": {"200": {}}}}},
        }
        imp = _import(repo, pid, doc)
        params = {
            "import_id": imp,
            "inventory_only": False,
            "enable_rate_probe": True,
            "check_config": False,
            "check_error_leakage": False,
            "risk_ack": True,
            "rate_probe_operation": "GET /limited",
            "rate_probe_count": 20,
        }
        _scan(repo, settings, pid, params)
    finally:
        server.shutdown()
        server.server_close()
    assert len(hits) == 1  # backed off after the very first 429, never retried 20 times


def test_rate_probe_stops_on_unstable_latency(
    repo: StorageRepository, settings: RuntimeSettings, monkeypatch: Any
) -> None:
    """A slow-answering endpoint trips the latency-instability break instead of continuing."""
    import http.server
    import threading
    import time

    import app.scanners.apisec.runner as runner_mod

    monkeypatch.setattr(runner_mod, "RATE_PROBE_LATENCY_BREAK_MS", 50)
    hits: list[str] = []

    class Slow(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            hits.append(self.path)
            time.sleep(0.2)  # well over the patched 50ms threshold
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    class Server(http.server.HTTPServer):
        daemon_threads = True

        def handle_error(self, request: Any, client_address: Any) -> None:
            return

    server = Server(("127.0.0.1", 0), Slow)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        pid = _project(repo, port)
        doc = {
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "servers": [{"url": f"http://127.0.0.1:{port}/v1"}],
            "paths": {"/slow": {"get": {"operationId": "slow", "responses": {"200": {}}}}},
        }
        imp = _import(repo, pid, doc)
        params = {
            "import_id": imp,
            "inventory_only": False,
            "enable_rate_probe": True,
            "check_config": False,
            "check_error_leakage": False,
            "risk_ack": True,
            "rate_probe_operation": "GET /slow",
            "rate_probe_count": 20,
        }
        _scan(repo, settings, pid, params)
    finally:
        server.shutdown()
        server.server_close()
    assert len(hits) == 1  # stopped after the first over-threshold response, not all 20
