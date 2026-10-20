"""Phase 03 verification: focused SSRF / scope-bypass suite against REAL local servers.

Two loopback HTTP servers run for the whole module:
  * LAB    - the authorized fixture target (reachable only via an audited override for
             127.0.0.1/32, plus scope host `lab.test` and the lab port);
  * VICTIM - an "internal service" on another port that must NEVER receive a request.

Every attack goes through the real guard (`ScopeGuard` + `GuardedRequester`) with a
transport that genuinely sends HTTP to the guard's pinned IP. After each attack we
assert the victim's request log is empty and the block was recorded with a reason.
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

T0 = datetime.now(UTC)


def _server(
    handler_cls: type[BaseHTTPRequestHandler],
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class VictimHandler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"internal secret")

    def log_message(self, *_a: object) -> None:
        return


class LabHandler(BaseHTTPRequestHandler):
    hits: list[str] = []
    redirect_to: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        location = type(self).redirect_to.get(self.path)
        if location is not None:
            self.send_response(302)
            self.send_header("Location", location)
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *_a: object) -> None:
        return


@pytest.fixture(scope="module")
def servers() -> Iterator[tuple[int, int]]:
    lab, _ = _server(LabHandler)
    victim, _ = _server(VictimHandler)
    try:
        yield lab.server_address[1], victim.server_address[1]
    finally:
        for s in (lab, victim):
            s.shutdown()
            s.server_close()


@pytest.fixture(autouse=True)
def _reset_logs() -> None:
    LabHandler.hits = []
    LabHandler.redirect_to = {}
    VictimHandler.hits = []


@dataclass
class Resolver:
    table: dict[str, list[list[str]]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        answers = self.table.get(host)
        if not answers:
            raise ResolutionError("NXDOMAIN")
        return answers.pop(0) if len(answers) > 1 else answers[0]


class RealHttpTransport:
    """Sends real HTTP, but only ever to the guard's pinned IP and the authorized port."""

    def send(
        self, method: str, authorized: AuthorizedTarget, options: object = None
    ) -> TransportResponse:
        conn = http.client.HTTPConnection(
            authorized.pinned_ips[0], authorized.target.port, timeout=5
        )
        try:
            conn.request(method, authorized.target.path, headers={"Host": authorized.target.host})
            resp = conn.getresponse()
            resp.read()
            return TransportResponse(status=resp.status, location=resp.getheader("Location"))
        finally:
            conn.close()


def lab_project(
    lab_port: int,
    *,
    end: datetime | None = None,
    extra_hosts: list[str] | None = None,
    attested: bool = True,
    authorized: bool = True,
) -> Project:
    override = InternalTargetOverride(
        ip_ranges=["127.0.0.1/32"],
        reason="local fixture lab for SSRF suite",
        expires_at=T0 + timedelta(hours=1),
        audit_event_id=new_id("event"),
    )
    scope = ScopeDefinition(
        schemes=["http"],
        hosts=["lab.test", *(extra_hosts or [])],
        ports=[lab_port],
        path_prefixes=["/app"],
        exclusions={"path_prefixes": ["/app/private"], "ports": [22]},
        internal_override=override,
    )
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=T0 - timedelta(days=1),
        window_end=end or T0 + timedelta(days=1),
        attestation_event_id=new_id("event") if attested else None,
    )
    return make_project(scope=scope, authorization=auth if authorized else None)


def attack(
    project: Project, url: str, resolver: Resolver | None = None
) -> tuple[Reason | None, MemorySink]:
    sink = MemorySink()
    guard = ScopeGuard(
        project, resolver=resolver or Resolver({"lab.test": [["127.0.0.1"]]}), sink=sink
    )
    try:
        GuardedRequester(guard, RealHttpTransport()).request("GET", url)
    except ScopeBlocked as exc:
        return exc.decision.reason, sink
    return None, sink


def test_lab_is_reachable_through_the_guard(servers: tuple[int, int]) -> None:
    lab_port, _ = servers
    reason, sink = attack(lab_project(lab_port), f"http://lab.test:{lab_port}/app/ok")
    assert reason is None and LabHandler.hits == ["/app/ok"]
    assert all(d.allowed for d in sink.decisions)


def _redirect_targets(victim: int) -> list[tuple[str, str]]:
    return [
        ("loopback literal", f"http://127.0.0.1:{victim}/"),
        ("loopback other address", f"http://127.0.0.2:{victim}/"),
        ("localhost name", f"http://localhost:{victim}/"),
        ("IPv6 loopback", f"http://[::1]:{victim}/"),
        ("IPv4-mapped IPv6 loopback", f"http://[::ffff:127.0.0.1]:{victim}/"),
        ("NAT64 loopback", f"http://[64:ff9b::7f00:1]:{victim}/"),
        ("decimal integer host", f"http://2130706433:{victim}/"),
        ("hex host", f"http://0x7f000001:{victim}/"),
        ("short dotted host", f"http://127.1:{victim}/"),
        ("octal dotted host", f"http://0177.0.0.1:{victim}/"),
        ("trailing-dot IP", f"http://127.0.0.1.:{victim}/"),
        ("private 10/8", "http://10.0.0.1/"),
        ("private 192.168/16", "http://192.168.1.1/"),
        ("link-local", "http://169.254.10.10/"),
        ("AWS/GCP metadata", "http://169.254.169.254/latest/meta-data/"),
        ("metadata via IPv6 mapped", "http://[::ffff:a9fe:a9fe]/latest/meta-data/"),
        ("Azure wire server", "http://168.63.129.16/"),
        ("Alibaba metadata", "http://100.100.100.200/latest/meta-data/"),
        ("user-info confusion", f"http://lab.test@127.0.0.1:{victim}/"),
        ("user-info with port", f"http://lab.test:{victim}@127.0.0.1:{victim}/"),
        ("protocol-relative", f"//127.0.0.1:{victim}/"),
        ("backslash host trick", f"http:\\\\127.0.0.1:{victim}/"),
        ("suffix confusion", f"http://lab.test.evil.test:{victim}/"),
        ("in-scope host, victim port", f"http://lab.test:{victim}/app/x"),
        ("in-scope host, excluded port", "http://lab.test:22/app/x"),
        ("scheme downgrade/change", f"https://lab.test:{victim}/app/x"),
        ("file scheme", "file:///etc/passwd"),
        ("gopher scheme", f"gopher://127.0.0.1:{victim}/_GET"),
        ("javascript scheme", "javascript:alert(document.domain)"),
        ("data scheme", "data:text/html,<script>alert(1)</script>"),
        ("encoded traversal out of prefix", "/app/%2e%2e/admin"),
        ("double-encoded traversal", "/app/%252e%252e/admin"),
        ("dot-segment traversal", "/app/../admin"),
        ("semicolon traversal", "/app/..;/admin"),
        ("excluded path", "/app/private/keys"),
        ("excluded path, case-encoded", "/app/%70rivate/keys"),
        ("whitespace smuggling", f"http://127.0.0.1:{victim}/ HTTP/1.1"),
        ("newline injection", f"http://lab.test/app\r\nHost: 127.0.0.1:{victim}"),
    ]


@pytest.mark.parametrize("index", range(38))
def test_every_redirect_attack_is_blocked_and_victim_sees_nothing(
    servers: tuple[int, int], index: int
) -> None:
    lab_port, victim_port = servers
    name, location = _redirect_targets(victim_port)[index]
    LabHandler.redirect_to = {"/app/start": location}
    resolver = Resolver(
        {
            "lab.test": [["127.0.0.1"]],
            "localhost": [["127.0.0.1"]],
            "lab.test.evil.test": [["127.0.0.1"]],
        }
    )
    reason, sink = attack(lab_project(lab_port), f"http://lab.test:{lab_port}/app/start", resolver)
    assert reason is not None, f"{name}: redirect to {location!r} was FOLLOWED"
    assert VictimHandler.hits == [], f"{name}: victim received {VictimHandler.hits}"
    assert LabHandler.hits == ["/app/start"], f"{name}: unexpected lab traffic {LabHandler.hits}"
    blocked = sink.blocked[-1]
    assert blocked.check == "redirect" or blocked.check == "resolved_ip", (name, blocked.check)
    assert blocked.reason == reason and blocked.message and blocked.scope_hash


@pytest.mark.parametrize(
    ("name", "url_fmt", "reason"),
    [
        ("direct victim literal", "http://127.0.0.1:{v}/", Reason.IP_OUT_OF_SCOPE),
        ("direct victim via in-scope name", "http://lab.test:{v}/app", Reason.PORT_NOT_ALLOWED),
        (
            "IDN look-alike of lab.test",
            "http://lаb.test:{l}/app",
            Reason.HOST_OUT_OF_SCOPE,
        ),  # Cyrillic 'а'
        ("fullwidth dot suffix", "http://lab.test．evil.test:{l}/app", Reason.HOST_OUT_OF_SCOPE),
        ("IPv6 zone id", "http://[fe80::1%25lo]:{v}/", Reason.AMBIGUOUS_HOST),
        ("encoded host", "http://lab%2etest:{l}/app", Reason.AMBIGUOUS_HOST),
        ("outside path prefix", "http://lab.test:{l}/admin", Reason.PATH_OUT_OF_SCOPE),
        ("excluded path", "http://lab.test:{l}/app/private", Reason.PATH_EXCLUDED),
    ],
)
def test_direct_attacks_never_touch_either_server(
    servers: tuple[int, int], name: str, url_fmt: str, reason: Reason
) -> None:
    lab_port, victim_port = servers
    got, _ = attack(lab_project(lab_port), url_fmt.format(v=victim_port, l=lab_port))
    assert got == reason, name
    assert VictimHandler.hits == [] and LabHandler.hits == []


def test_idn_hostnames_canonicalize_consistently(servers: tuple[int, int]) -> None:
    """A Unicode spelling that IDNA maps to the in-scope name reaches the in-scope host only."""
    lab_port, _ = servers
    reason, _ = attack(lab_project(lab_port), f"http://LAB.TEST.:{lab_port}/app/case")
    assert reason is None and LabHandler.hits == ["/app/case"]


def test_dns_rebinding_between_requests_is_blocked(servers: tuple[int, int]) -> None:
    lab_port, _ = servers
    # Second answer for the in-scope name points at a private address the override does not cover.
    resolver = Resolver({"lab.test": [["127.0.0.1"], ["10.0.0.7"]]})
    sink = MemorySink()
    guard = ScopeGuard(lab_project(lab_port), resolver=resolver, sink=sink)
    requester = GuardedRequester(guard, RealHttpTransport())
    requester.request("GET", f"http://lab.test:{lab_port}/app/one")
    with pytest.raises(ScopeBlocked) as info:
        requester.request("GET", f"http://lab.test:{lab_port}/app/two")
    assert info.value.decision.reason == Reason.IP_BLOCKED_RANGE
    assert LabHandler.hits == ["/app/one"]


def test_rebinding_inside_redirect_chain_is_blocked(servers: tuple[int, int]) -> None:
    lab_port, _ = servers
    LabHandler.redirect_to = {"/app/a": f"http://second.lab.test:{lab_port}/app/b"}
    project = lab_project(lab_port, extra_hosts=["second.lab.test"])
    resolver = Resolver({"lab.test": [["127.0.0.1"]], "second.lab.test": [["169.254.169.254"]]})
    reason, _ = attack(project, f"http://lab.test:{lab_port}/app/a", resolver)
    assert reason == Reason.IP_CLOUD_METADATA
    assert LabHandler.hits == ["/app/a"]


def test_mixed_dns_answers_block_the_whole_request(servers: tuple[int, int]) -> None:
    lab_port, _ = servers
    reason, _ = attack(
        lab_project(lab_port),
        f"http://lab.test:{lab_port}/app",
        Resolver({"lab.test": [["127.0.0.1", "192.168.0.10"]]}),
    )
    assert reason == Reason.IP_BLOCKED_RANGE and LabHandler.hits == []


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"end": T0 - timedelta(seconds=1)}, Reason.AUTHORIZATION_EXPIRED),
        ({"attested": False}, Reason.ATTESTATION_MISSING),
        ({"authorized": False}, Reason.AUTHORIZATION_MISSING),
    ],
)
def test_authorization_failures_send_nothing(
    servers: tuple[int, int], kwargs: dict[str, Any], reason: Reason
) -> None:
    lab_port, _ = servers
    resolver = Resolver({"lab.test": [["127.0.0.1"]]})
    got, _ = attack(lab_project(lab_port, **kwargs), f"http://lab.test:{lab_port}/app", resolver)
    assert got == reason and LabHandler.hits == [] and resolver.calls == []


def test_expired_override_makes_lab_unreachable(servers: tuple[int, int]) -> None:
    lab_port, _ = servers
    project = lab_project(lab_port)
    assert project.scope.internal_override is not None
    expired = project.model_copy(
        update={
            "scope": project.scope.model_copy(
                update={
                    "internal_override": project.scope.internal_override.model_copy(
                        update={"expires_at": T0 - timedelta(seconds=1)}
                    )
                }
            )
        }
    )
    reason, _ = attack(expired, f"http://lab.test:{lab_port}/app")
    assert reason == Reason.IP_BLOCKED_RANGE and LabHandler.hits == []


# ---------------------------------------------------------------------- discovered subdomains


@pytest.mark.parametrize(
    ("host", "status"),
    [
        ("dev.lab.test", ScopeStatus.PENDING_APPROVAL),  # child of an exact in-scope host
        ("a.b.lab.test", ScopeStatus.PENDING_APPROVAL),
        ("lab.test.evil.test", ScopeStatus.OUT_OF_SCOPE),
        ("evil.test", ScopeStatus.OUT_OF_SCOPE),
        ("lab.test", ScopeStatus.IN_SCOPE),
    ],
)
def test_discovered_subdomains_are_not_approved_by_successful_dns(
    servers: tuple[int, int], host: str, status: ScopeStatus
) -> None:
    lab_port, _ = servers
    resolver = Resolver(
        {
            h: [["127.0.0.1"]]
            for h in ("dev.lab.test", "a.b.lab.test", "lab.test.evil.test", "evil.test", "lab.test")
        }
    )
    guard = ScopeGuard(lab_project(lab_port), resolver=resolver, sink=MemorySink())
    got, decision = guard.classify_discovered_host(host)
    assert got == status and resolver.calls == []  # classification never even resolves
    if status != ScopeStatus.IN_SCOPE:
        assert not decision.allowed
        # ...and even though the name resolves to the (overridden) lab IP, requests are refused
        with pytest.raises(ScopeBlocked) as info:
            GuardedRequester(guard, RealHttpTransport()).request(
                "GET", f"http://{host}:{lab_port}/app"
            )
        assert info.value.decision.reason == Reason.HOST_OUT_OF_SCOPE
    assert LabHandler.hits == [] and VictimHandler.hits == []
