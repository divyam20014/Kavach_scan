"""Acceptance tests for the policy hook: out-of-scope targets never reach the transport.

Includes a real local HTTP fixture server that records every request it receives,
proving blocked hosts/IPs/paths/redirects generate zero traffic.
"""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from app.models import new_id
from app.models.common import ScopeStatus
from app.models.project import AuthorizationRecord, InternalTargetOverride, Project, ScopeDefinition
from app.scope import (
    AuthorizedTarget,
    GuardedRequester,
    MemorySink,
    Reason,
    ResolutionError,
    ScopeBlocked,
    ScopeGuard,
    TransportResponse,
)
from tests.conftest import make_project

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


@dataclass
class FakeResolver:
    answers: dict[str, list[list[str]]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        seq = self.answers.get(host)
        if not seq:
            raise ResolutionError("NXDOMAIN")
        return seq.pop(0) if len(seq) > 1 else seq[0]


@dataclass
class RecordingTransport:
    """Stands in for the Phase 05 HTTP transport; records every call it receives."""

    routes: dict[str, TransportResponse] = field(default_factory=dict)
    sent: list[tuple[str, str, tuple[str, ...]]] = field(default_factory=list)

    def send(self, method: str, authorized: AuthorizedTarget) -> TransportResponse:
        self.sent.append((method, authorized.target.url, authorized.pinned_ips))
        return self.routes.get(authorized.target.url, TransportResponse(status=200))


def make(
    scope: dict[str, Any],
    *,
    override: InternalTargetOverride | None = None,
    end: datetime = T0 + timedelta(days=5),
    status: str = "active",
) -> Project:
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=T0 - timedelta(days=1),
        window_end=end,
        attestation_event_id=new_id("event"),
    )
    return make_project(
        authorization=auth,
        scope=ScopeDefinition(**scope, internal_override=override),
        status=status,
    )


SCOPE = {
    "schemes": ["https"],
    "hosts": ["app.example.com"],
    "wildcard_domains": ["*.svc.example.com"],
    "ports": [443],
    "path_prefixes": ["/app"],
    "exclusions": {"path_prefixes": ["/app/logout"]},
}


def guard_for(
    project: Project,
    resolver: FakeResolver,
    clock: Clock | None = None,
    kill: list[bool] | None = None,
) -> tuple[ScopeGuard, MemorySink]:
    sink = MemorySink()
    kill_flag = kill if kill is not None else [False]
    return ScopeGuard(
        project,
        resolver=resolver,
        sink=sink,
        clock=clock or Clock(),
        kill_switch=lambda: kill_flag[0],
    ), sink


PUBLIC = "93.184.216.34"


@pytest.mark.parametrize(
    ("url", "answers", "reason"),
    [
        ("https://evil.test/app", {}, Reason.HOST_OUT_OF_SCOPE),
        ("https://app.example.com.evil.test/app", {}, Reason.HOST_OUT_OF_SCOPE),
        ("https://app.example.com/admin", {}, Reason.PATH_OUT_OF_SCOPE),
        ("https://app.example.com/app/logout", {}, Reason.PATH_EXCLUDED),
        ("https://app.example.com/app/%2e%2e/admin", {}, Reason.PATH_OUT_OF_SCOPE),
        ("https://app.example.com:8443/app", {}, Reason.PORT_NOT_ALLOWED),
        ("http://app.example.com/app", {}, Reason.SCHEME_NOT_ALLOWED),
        ("https://169.254.169.254/app", {}, Reason.IP_OUT_OF_SCOPE),
        (
            "https://app.example.com/app",
            {"app.example.com": [["127.0.0.1"]]},
            Reason.IP_BLOCKED_RANGE,
        ),
        (
            "https://app.example.com/app",
            {"app.example.com": [["169.254.169.254"]]},
            Reason.IP_CLOUD_METADATA,
        ),
        (
            "https://app.example.com/app",
            {"app.example.com": [[PUBLIC, "10.0.0.5"]]},
            Reason.IP_BLOCKED_RANGE,
        ),
        (
            "https://app.example.com/app",
            {"app.example.com": [["::ffff:127.0.0.1"]]},
            Reason.IP_BLOCKED_RANGE,
        ),
        (
            "https://app.example.com/app",
            {"app.example.com": [["64:ff9b::a9fe:a9fe"]]},
            Reason.IP_CLOUD_METADATA,
        ),
        ("https://app.example.com/app", {}, Reason.RESOLUTION_FAILED),
        ("https://app.example.com/app", {"app.example.com": [[]]}, Reason.NO_ADDRESSES),
    ],
)
def test_blocked_requests_never_reach_the_transport(
    url: str, answers: dict[str, list[list[str]]], reason: Reason
) -> None:
    guard, sink = guard_for(make(SCOPE), FakeResolver(answers))
    transport = RecordingTransport()
    with pytest.raises(ScopeBlocked) as info:
        GuardedRequester(guard, transport).request("GET", url)
    assert info.value.decision.reason == reason
    assert transport.sent == []  # nothing reached the request adapter
    assert sink.blocked and sink.blocked[-1].reason == reason  # the block is a recorded event


def test_allowed_request_is_pinned_to_validated_ips() -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC, "2606:2800:220:1:248:1893:25c8:1946"]]})
    guard, sink = guard_for(make(SCOPE), resolver)
    transport = RecordingTransport()
    response, chain = GuardedRequester(guard, transport).request(
        "GET", "https://APP.example.com/app/x"
    )
    assert response.status == 200 and chain == ["https://app.example.com/app/x"]
    assert transport.sent == [
        ("GET", "https://app.example.com/app/x", (PUBLIC, "2606:2800:220:1:248:1893:25c8:1946"))
    ]
    assert all(d.allowed for d in sink.decisions) and {d.check for d in sink.decisions} == {
        "target",
        "resolved_ip",
    }


def test_out_of_scope_redirect_is_not_followed() -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC]], "evil.test": [[PUBLIC]]})
    guard, sink = guard_for(make(SCOPE), resolver)
    transport = RecordingTransport(
        routes={
            "https://app.example.com/app": TransportResponse(
                302, location="https://evil.test/steal"
            ),
        }
    )
    with pytest.raises(ScopeBlocked) as info:
        GuardedRequester(guard, transport).request("GET", "https://app.example.com/app")
    assert (
        info.value.decision.reason == Reason.HOST_OUT_OF_SCOPE
        and info.value.decision.check == "redirect"
    )
    assert [u for _, u, _ in transport.sent] == [
        "https://app.example.com/app"
    ]  # evil.test never contacted
    assert "evil.test" not in resolver.calls  # not even resolved


def test_redirect_to_in_scope_host_resolving_private_is_blocked() -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC]], "a.svc.example.com": [["10.1.2.3"]]})
    guard, _ = guard_for(make(SCOPE), resolver)
    transport = RecordingTransport(
        routes={
            "https://app.example.com/app": TransportResponse(
                301, location="https://a.svc.example.com/app"
            ),
        }
    )
    with pytest.raises(ScopeBlocked) as info:
        GuardedRequester(guard, transport).request("GET", "https://app.example.com/app")
    assert info.value.decision.reason == Reason.IP_BLOCKED_RANGE
    assert len(transport.sent) == 1


def test_redirect_chain_within_scope_and_limit() -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC]]})
    guard, _ = guard_for(make(SCOPE), resolver)
    loop = {
        f"https://app.example.com/app/{i}": TransportResponse(302, location=f"/app/{i + 1}")
        for i in range(20)
    }
    transport = RecordingTransport(routes=loop)
    with pytest.raises(ScopeBlocked) as info:
        GuardedRequester(guard, transport, max_redirects=3).request(
            "GET", "https://app.example.com/app/0"
        )
    assert info.value.decision.reason == Reason.REDIRECT_LIMIT
    assert len(transport.sent) == 4


def test_dns_rebinding_second_answer_private_is_blocked() -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC], ["127.0.0.1"]]})
    guard, _ = guard_for(make(SCOPE), resolver)
    first = guard.authorize_request("https://app.example.com/app")
    assert first.pinned_ips == (PUBLIC,)  # connection is pinned to the checked address
    with pytest.raises(ScopeBlocked) as info:
        guard.authorize_request("https://app.example.com/app/2")
    assert info.value.decision.reason == Reason.IP_BLOCKED_RANGE


@pytest.mark.parametrize(
    ("project_kw", "clock", "reason"),
    [
        ({"end": T0 - timedelta(seconds=1)}, Clock(), Reason.AUTHORIZATION_EXPIRED),
        ({"status": "archived"}, Clock(), Reason.PROJECT_ARCHIVED),
    ],
)
def test_authorization_gate_blocks_before_anything_else(
    project_kw: dict[str, Any], clock: Clock, reason: Reason
) -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC]]})
    guard, sink = guard_for(make(SCOPE, **project_kw), resolver, clock)
    transport = RecordingTransport()
    with pytest.raises(ScopeBlocked) as info:
        GuardedRequester(guard, transport).request("GET", "https://app.example.com/app")
    assert info.value.decision.reason == reason
    assert transport.sent == [] and resolver.calls == []


def test_missing_authorization_blocks_active_work() -> None:
    guard = ScopeGuard(
        make_project(authorization=None, scope=ScopeDefinition(**SCOPE)),
        resolver=FakeResolver({"app.example.com": [[PUBLIC]]}),
        sink=MemorySink(),
        clock=Clock(),
    )
    with pytest.raises(ScopeBlocked) as info:
        guard.authorize_request("https://app.example.com/app")
    assert info.value.decision.reason == Reason.AUTHORIZATION_MISSING


def test_scan_crossing_window_end_stops_mid_run() -> None:
    clock = Clock()
    resolver = FakeResolver({"app.example.com": [[PUBLIC]]})
    guard, _ = guard_for(make(SCOPE, end=T0 + timedelta(minutes=5)), resolver, clock)
    transport = RecordingTransport()
    requester = GuardedRequester(guard, transport)
    requester.request("GET", "https://app.example.com/app/1")
    clock.now = T0 + timedelta(minutes=5)
    with pytest.raises(ScopeBlocked) as info:
        requester.request("GET", "https://app.example.com/app/2")
    assert info.value.decision.reason == Reason.AUTHORIZATION_EXPIRED
    assert len(transport.sent) == 1


def test_kill_switch_blocks_everything() -> None:
    kill = [False]
    guard, _ = guard_for(make(SCOPE), FakeResolver({"app.example.com": [[PUBLIC]]}), kill=kill)
    transport = RecordingTransport()
    GuardedRequester(guard, transport).request("GET", "https://app.example.com/app")
    kill[0] = True
    with pytest.raises(ScopeBlocked) as info:
        GuardedRequester(guard, transport).request("GET", "https://app.example.com/app")
    assert info.value.decision.reason == Reason.KILL_SWITCH and len(transport.sent) == 1


def test_connect_and_subprocess_targets_are_gated() -> None:
    resolver = FakeResolver({"app.example.com": [[PUBLIC]], "db.example.com": [[PUBLIC]]})
    guard, _ = guard_for(make({**SCOPE, "ports": [443, 22]}), resolver)
    assert guard.authorize_connect("app.example.com", 22).pinned_ips == (PUBLIC,)
    with pytest.raises(ScopeBlocked) as info:
        guard.authorize_connect("app.example.com", 3306)
    assert info.value.decision.reason == Reason.PORT_NOT_ALLOWED
    with pytest.raises(ScopeBlocked):
        guard.authorize_subprocess_targets(["app.example.com", "db.example.com"], [443])
    with pytest.raises(ScopeBlocked) as info:
        guard.authorize_connect("127.1", 443)
    assert info.value.decision.reason == Reason.AMBIGUOUS_HOST


def test_discovered_subdomains_need_scope_not_dns() -> None:
    guard, sink = guard_for(make(SCOPE), FakeResolver({"new.svc.example.com": [[PUBLIC]]}))
    assert guard.classify_discovered_host("new.svc.example.com")[0] == ScopeStatus.IN_SCOPE
    status, decision = guard.classify_discovered_host("dev.app.example.com")
    assert status == ScopeStatus.PENDING_APPROVAL and not decision.allowed
    assert guard.classify_discovered_host("evil.test")[0] == ScopeStatus.OUT_OF_SCOPE
    assert guard.resolver.calls == []  # type: ignore[attr-defined]  # classification never resolves


# ---------------------------------------------------------------------- real local fixture server


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        if self.path == "/app/redirect-out":
            self.send_response(302)
            self.send_header("Location", "https://evil.test/x")
        elif self.path == "/app/redirect-meta":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def fixture_server() -> Iterator[tuple[int, list[str]]]:
    _Handler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], _Handler.hits
    finally:
        server.shutdown()
        server.server_close()


class LoopbackHttpTransport:
    """Test-only transport that really sends HTTP, but only to the guard's pinned IPs."""

    def __init__(self, port: int) -> None:
        self.port = port

    def send(self, method: str, authorized: AuthorizedTarget) -> TransportResponse:
        conn = http.client.HTTPConnection(authorized.pinned_ips[0], self.port, timeout=5)
        try:
            conn.request(method, authorized.target.path, headers={"Host": authorized.target.host})
            resp = conn.getresponse()
            return TransportResponse(status=resp.status, location=resp.getheader("Location"))
        finally:
            conn.close()


def test_fixture_server_receives_zero_requests_for_blocked_targets(
    fixture_server: tuple[int, list[str]],
) -> None:
    port, hits = fixture_server
    scope = {
        "schemes": ["http"],
        "hosts": ["lab.test"],
        "ip_ranges": ["127.0.0.1/32"],
        "ports": [port],
        "path_prefixes": ["/app"],
    }
    no_override = make(scope)
    guard, sink = guard_for(no_override, FakeResolver({"lab.test": [["127.0.0.1"]]}))
    requester = GuardedRequester(guard, LoopbackHttpTransport(port))
    for url in (
        f"http://lab.test:{port}/app",
        f"http://127.0.0.1:{port}/app",
        f"http://lab.test:{port}/admin",
    ):
        with pytest.raises(ScopeBlocked):
            requester.request("GET", url)
    assert hits == []  # loopback is blocked by default: the server saw nothing
    assert len(sink.blocked) == 3


def test_fixture_server_reachable_only_with_audited_override(
    fixture_server: tuple[int, list[str]],
) -> None:
    port, hits = fixture_server
    override = InternalTargetOverride(
        ip_ranges=["127.0.0.1/32"],
        reason="local fixture server for tests",
        expires_at=T0 + timedelta(hours=1),
        audit_event_id=new_id("event"),
    )
    scope = {
        "schemes": ["http"],
        "hosts": ["lab.test"],
        "ports": [port],
        "path_prefixes": ["/app"],
        "exclusions": {"path_prefixes": ["/app/private"]},
    }
    guard, sink = guard_for(
        make(scope, override=override), FakeResolver({"lab.test": [["127.0.0.1"]]})
    )
    requester = GuardedRequester(guard, LoopbackHttpTransport(port))
    assert requester.request("GET", f"http://lab.test:{port}/app/ok")[0].status == 200
    for url in (
        f"http://lab.test:{port}/app/private",
        f"http://lab.test:{port}/app/redirect-out",
        f"http://lab.test:{port}/app/redirect-meta",
    ):
        with pytest.raises(ScopeBlocked):
            requester.request("GET", url)
    # Only in-scope paths arrived; redirect destinations were never requested.
    assert hits == ["/app/ok", "/app/redirect-out", "/app/redirect-meta"]
    assert [d.reason for d in sink.blocked] == [
        Reason.PATH_EXCLUDED,  # /app/private
        Reason.SCHEME_NOT_ALLOWED,  # redirect to https://evil.test (scope is http-only)
        Reason.IP_OUT_OF_SCOPE,  # redirect to the metadata IP literal
    ]
