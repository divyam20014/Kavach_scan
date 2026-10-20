"""Phase 05 shared adapters: pinned HTTP transport, request service, DNS cache, process
version capture and TLS-tool parsing. Real loopback servers log every request so tests
can prove what was (and was not) sent."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.integrations.dns import CachingResolver
from app.integrations.http_client import (
    HeaderPolicyError,
    HttpClientConfig,
    PinnedHttpTransport,
    TransportError,
    validate_request_headers,
)
from app.integrations.http_service import HttpService, retry_after_seconds
from app.integrations.process import capture_version, find_executable, run_process
from app.integrations.tls_tools import TlsToolSpec, ToolOutputError
from app.scope import (
    AuthorizedTarget,
    GuardedRequester,
    MemorySink,
    ResolutionError,
    ScopeGuard,
    Transport,
    normalize_target,
)
from app.scope.engine import Reason
from tests.webfixtures import LabHandler, MapResolver, VictimHandler, lab_project, lab_servers


@pytest.fixture
def ports() -> Iterator[tuple[int, int]]:
    with lab_servers() as p:
        yield p


def _authorized(url: str, ip: str = "127.0.0.1") -> AuthorizedTarget:
    return AuthorizedTarget(target=normalize_target(url), pinned_ips=(ip,), decisions=())


class FakeCtx:
    """Minimal ServiceContext: real guard + plain transport; records sleeps/counters."""

    def __init__(self, guard: ScopeGuard) -> None:
        self.guard = guard
        self.counters: dict[str, int] = {}
        self.sleeps: list[float] = []
        self.events: list[str] = []

    def requester(
        self, transport: Transport, *, max_redirects: int | None = None
    ) -> GuardedRequester:
        return GuardedRequester(self.guard, transport, max_redirects=max_redirects or 5)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        time.sleep(min(seconds, 1.5))

    def incr(self, counter: str, n: int = 1) -> None:
        self.counters[counter] = self.counters.get(counter, 0) + n

    def emit(self, type_: str, message: str, *, level: Any = "info", **data: Any) -> None:
        self.events.append(f"{type_}: {message}")


def _service(lab_port: int, **kw: Any) -> tuple[HttpService, FakeCtx, MemorySink]:
    sink = MemorySink()
    guard = ScopeGuard(lab_project([lab_port]), resolver=MapResolver(), sink=sink)
    ctx = FakeCtx(guard)
    config = kw.pop("config", HttpClientConfig(connect_timeout=2, read_timeout=2, total_timeout=5))
    return HttpService(ctx, PinnedHttpTransport(config), **kw), ctx, sink


# ---------------------------------------------------------------------- transport


def test_transport_connects_to_pinned_ip_and_sends_hostname(ports: tuple[int, int]) -> None:
    lab, _ = ports
    response = PinnedHttpTransport().send("GET", _authorized(f"http://lab.test:{lab}/echo-headers"))
    assert response.status == 200
    assert f"host=lab.test:{lab}".encode() in response.body
    assert response.peer_ip == "127.0.0.1"
    assert b"User-Agent" in response.body and b"Connection" in response.body
    assert LabHandler.hits[-1].headers["user-agent"].startswith("VAPT-Workbench/")


def test_transport_never_follows_redirects(ports: tuple[int, int]) -> None:
    lab, _ = ports
    response = PinnedHttpTransport().send(
        "GET", _authorized(f"http://lab.test:{lab}/redirect-same")
    )
    assert response.status == 301 and response.location == "/about"
    assert [h.path for h in LabHandler.hits] == ["/redirect-same"]


def test_ambient_proxy_settings_are_ignored(
    ports: tuple[int, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    lab, victim = ports
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{victim}")
    response = PinnedHttpTransport().send("GET", _authorized(f"http://lab.test:{lab}/about"))
    assert response.status == 200
    assert VictimHandler.hits == []  # the "proxy" never saw a request


def test_body_is_capped_and_flagged(ports: tuple[int, int]) -> None:
    lab, _ = ports
    transport = PinnedHttpTransport(HttpClientConfig(max_response_bytes=64 * 1024))
    response = transport.send("GET", _authorized(f"http://lab.test:{lab}/big"))
    assert response.truncated and len(response.body) <= 64 * 1024
    assert response.bytes_read <= 64 * 1024


def test_decompression_bomb_is_bounded(ports: tuple[int, int]) -> None:
    lab, _ = ports
    transport = PinnedHttpTransport(
        HttpClientConfig(max_response_bytes=1024 * 1024, max_decoded_bytes=256 * 1024)
    )
    response = transport.send("GET", _authorized(f"http://lab.test:{lab}/bomb"))
    assert response.truncated
    assert len(response.body) <= 256 * 1024


def test_read_timeout(ports: tuple[int, int]) -> None:
    lab, _ = ports
    transport = PinnedHttpTransport(HttpClientConfig(read_timeout=0.3))
    with pytest.raises(TransportError) as exc:
        transport.send("GET", _authorized(f"http://lab.test:{lab}/slow"))
    assert exc.value.kind == "timeout"


def test_total_timeout_stops_slow_drip(ports: tuple[int, int]) -> None:
    lab, _ = ports
    transport = PinnedHttpTransport(HttpClientConfig(read_timeout=2, total_timeout=0.5))
    started = time.monotonic()
    response = transport.send("GET", _authorized(f"http://lab.test:{lab}/drip"))
    assert response.truncated and time.monotonic() - started < 3


def test_connect_failure_is_reported(ports: tuple[int, int]) -> None:
    transport = PinnedHttpTransport(HttpClientConfig(connect_timeout=0.5))
    with pytest.raises(TransportError) as exc:
        transport.send("GET", _authorized("http://lab.test:9/"))
    assert exc.value.kind == "connect"


@pytest.mark.parametrize(
    "headers",
    [
        (("X-Test", "a\r\nInjected: 1"),),
        (("X-Test", "a\nb"),),
        (("Bad Name", "x"),),
        (("Host", "evil.test"),),
        (("Transfer-Encoding", "chunked"),),
        (("Content-Length", "5"),),
        (("Proxy-Authorization", "x"),),
    ],
)
def test_header_policy_rejects_before_sending(ports: tuple[int, int], headers: Any) -> None:
    lab, _ = ports
    from app.scope import RequestOptions

    with pytest.raises(HeaderPolicyError):
        PinnedHttpTransport().send(
            "GET", _authorized(f"http://lab.test:{lab}/about"), RequestOptions(headers=headers)
        )
    assert LabHandler.hits == []


def test_methods_are_restricted(ports: tuple[int, int]) -> None:
    lab, _ = ports
    for method in ("DELETE", "PUT", "TRACE", "CONNECT"):
        with pytest.raises(HeaderPolicyError):
            PinnedHttpTransport().send(method, _authorized(f"http://lab.test:{lab}/"))
    assert LabHandler.hits == []


def test_valid_custom_headers_pass() -> None:
    assert validate_request_headers((("Origin", "https://x.invalid"),)) == [
        ("Origin", "https://x.invalid")
    ]


# ---------------------------------------------------------------------- request service


def test_service_scope_blocks_before_any_traffic(ports: tuple[int, int]) -> None:
    lab, victim = ports
    service, _, sink = _service(lab)
    for url in (
        f"http://victim.test:{victim}/",  # host not in scope
        f"http://lab.test:{victim}/",  # port not in scope
        f"http://lab.test:{lab}/private/keys",  # excluded path
        "file:///etc/passwd",
    ):
        exchange = service.fetch("GET", url)
        assert exchange.blocked is not None and exchange.response is None, url
    assert LabHandler.hits == [] and VictimHandler.hits == []
    assert len(sink.blocked) == 4


def test_service_records_offscope_redirect_without_following(ports: tuple[int, int]) -> None:
    lab, victim = ports
    service, ctx, sink = _service(lab)
    exchange = service.fetch(
        "GET", f"http://lab.test:{lab}/go?next=http%3A%2F%2Fvictim.test%3A{victim}%2Fsteal"
    )
    assert exchange.redirect_blocked is not None
    assert exchange.status == 302
    assert VictimHandler.hits == []
    assert ctx.counters["redirects_blocked"] == 1
    assert sink.blocked[-1].check == "redirect"


def test_service_follows_validated_same_scope_redirect(ports: tuple[int, int]) -> None:
    lab, _ = ports
    service, _, _ = _service(lab)
    exchange = service.fetch("GET", f"http://lab.test:{lab}/redirect-same")
    assert exchange.status == 200
    assert [h.status for h in exchange.hops] == [301, 200]
    assert exchange.final_url.endswith("/about")


def test_service_honours_retry_after(ports: tuple[int, int]) -> None:
    lab, _ = ports
    service, ctx, _ = _service(lab)
    exchange = service.fetch("GET", f"http://lab.test:{lab}/limited")
    assert exchange.status == 200
    assert ctx.counters["rate_limited_responses"] == 1
    assert ctx.sleeps and ctx.sleeps[0] >= 0.9  # Retry-After: 1 honoured
    assert [h.path for h in LabHandler.hits] == ["/limited", "/limited"]


def test_service_retries_connect_errors_boundedly() -> None:
    guard = ScopeGuard(lab_project([9]), resolver=MapResolver(), sink=MemorySink())
    ctx = FakeCtx(guard)
    service = HttpService(
        ctx,
        PinnedHttpTransport(HttpClientConfig(connect_timeout=0.3)),
        max_retries=2,
        backoff_base=0.01,
    )
    exchange = service.fetch("GET", "http://lab.test:9/")
    assert exchange.error_kind == "connect" and exchange.attempts == 3
    assert ctx.counters["request_retries"] == 2
    post = service.fetch("POST", "http://lab.test:9/", body=b"x")
    assert post.attempts == 1  # non-idempotent: never retried


def test_retry_after_parsing() -> None:
    assert retry_after_seconds("7") == 7.0
    now = datetime(2026, 10, 21, tzinfo=UTC)
    assert retry_after_seconds("Wed, 21 Oct 2026 00:00:30 GMT", now=now) == 30.0
    assert retry_after_seconds("garbage") is None and retry_after_seconds(None) is None


def test_dns_rebinding_cannot_reach_a_blocked_address(ports: tuple[int, int]) -> None:
    """Resolution happens in the guard; the transport only ever sees validated pinned IPs."""
    lab, _ = ports
    resolver = MapResolver({"lab.test": ["169.254.169.254"]})  # metadata: never overridable
    guard = ScopeGuard(lab_project([lab]), resolver=resolver, sink=MemorySink())
    service = HttpService(FakeCtx(guard), PinnedHttpTransport())
    exchange = service.fetch("GET", f"http://lab.test:{lab}/")
    assert exchange.blocked is not None and LabHandler.hits == []


# ---------------------------------------------------------------------- DNS cache


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_dns_cache_ttl_and_rebinding_revalidation() -> None:
    answers = [["93.184.216.34"], ["127.0.0.1"]]
    clock = FakeClock()
    resolver = CachingResolver(lambda _h: answers.pop(0), ttl_seconds=30, clock=clock)
    assert resolver.resolve("app.example.com") == ["93.184.216.34"]
    clock.t = 10
    assert resolver.resolve("APP.example.com.") == ["93.184.216.34"]  # cached, same key
    assert resolver.lookups == 1
    clock.t = 31
    assert resolver.resolve("app.example.com") == ["127.0.0.1"]  # re-resolved after TTL
    assert resolver.lookups == 2


def test_dns_guard_validates_cached_answers_every_time() -> None:
    from app.models.project import ScopeDefinition

    clock = FakeClock()
    resolver = CachingResolver(lambda _h: ["10.0.0.5"], ttl_seconds=300, clock=clock)
    project = lab_project([80]).model_copy(
        update={"scope": ScopeDefinition(schemes=["http"], hosts=["lab.test"], ports=[80])}
    )
    sink = MemorySink()
    guard = ScopeGuard(project, resolver=resolver, sink=sink)
    for _ in range(3):
        with pytest.raises(Exception):  # noqa: B017 - ScopeBlocked each time, from cache
            guard.authorize_request("http://lab.test/")
    assert resolver.lookups == 1 and len(sink.blocked) == 3
    assert all(d.reason == Reason.IP_BLOCKED_RANGE for d in sink.blocked)


def test_dns_negative_cache_timeout_and_bounds() -> None:
    clock = FakeClock()
    calls: list[str] = []

    def failing(host: str) -> list[str]:
        calls.append(host)
        raise ResolutionError("NXDOMAIN")

    resolver = CachingResolver(failing, negative_ttl_seconds=5, clock=clock)
    for _ in range(3):
        with pytest.raises(ResolutionError):
            resolver.resolve("nx.example.com")
    assert len(calls) == 1

    hang = threading.Event()
    slow = CachingResolver(lambda _h: [hang.wait(5) and "1.2.3.4"], timeout_seconds=0.2)  # type: ignore[list-item]
    started = time.monotonic()
    with pytest.raises(ResolutionError, match="timed out"):
        slow.resolve("slow.example.com")
    hang.set()
    assert time.monotonic() - started < 2

    small = CachingResolver(lambda h: ["93.184.216.34"], max_entries=2)
    for host in ("a.example", "b.example", "c.example"):
        small.resolve(host)
    small.resolve("a.example")
    assert small.lookups == 4  # "a" was evicted
    assert CachingResolver(failing).resolve("127.0.0.1") == ["127.0.0.1"]  # literal: no lookup


# ---------------------------------------------------------------------- process additions


def test_capture_version_and_temp_dir(tmp_path: Path) -> None:
    version = capture_version(sys.executable, cwd=tmp_path)
    assert version.startswith("Python 3")
    temp = tmp_path / "tmp"
    temp.mkdir()
    result = run_process(
        [sys.executable, "-c", "import os;print(os.environ['TEMP'])"],
        allowed_executables=[sys.executable],
        cwd=tmp_path,
        timeout=30,
        temp_dir=temp,
    )
    assert result.stdout.decode().strip() == str(temp)
    assert find_executable(["definitely-not-a-real-tool-xyz"]) is None


# ---------------------------------------------------------------------- TLS tool parsing

SSLYZE_SAMPLE = b"""{"server_scan_results": [{"scan_status": "COMPLETED", "scan_result": {
 "ssl_2_0_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": []}},
 "ssl_3_0_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": []}},
 "tls_1_0_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": [
     {"cipher_suite": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}}]}},
 "tls_1_1_cipher_suites": {"status": "ERROR"},
 "tls_1_2_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": [
     {"cipher_suite": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}]}},
 "tls_1_3_cipher_suites": {"status": "COMPLETED", "result": {"accepted_cipher_suites": []}}
}}]}"""


def test_sslyze_parsing_and_argv() -> None:
    spec = TlsToolSpec("sslyze", "/opt/sslyze")
    report = spec.parse(SSLYZE_SAMPLE, "sslyze 6.0.0")
    assert report.protocols["TLS 1.0"] is True and report.protocols["TLS 1.3"] is False
    assert "TLS 1.1" not in report.protocols  # errored: no claim either way
    assert report.legacy_offered == ["TLS 1.0"]
    argv = spec.argv("lab.test", 443, "203.0.113.5")
    assert argv[-1] == "lab.test:443{203.0.113.5}"  # pinned IP: the tool does not resolve
    assert not any(a in argv for a in ("--heartbleed", "--robot", "--reneg", "--openssl_ccs"))


def test_testssl_parsing_and_argv() -> None:
    spec = TlsToolSpec("testssl.sh", "/opt/testssl.sh", output_file="t.json")
    data = (
        b'[{"id":"SSLv3","finding":"not offered"},{"id":"TLS1","finding":"offered (deprecated)"},'
        b'{"id":"TLS1_2","finding":"offered"}]'
    )
    report = spec.parse(data, "3.2")
    assert report.legacy_offered == ["TLS 1.0"] and report.protocols["SSLv3"] is False
    argv = spec.argv("lab.test", 8443, "203.0.113.5", json_path="/work/t.json")
    assert argv[argv.index("--ip") + 1] == "203.0.113.5" and "--protocols" in argv


@pytest.mark.parametrize(
    "raw", [b"", b"not json", b"{}", b'{"server_scan_results": []}', b"\xff\xfe"]
)
def test_tool_output_garbage_yields_no_claims(raw: bytes) -> None:
    with pytest.raises(ToolOutputError):
        TlsToolSpec("sslyze", "/x").parse(raw, "v")


def test_expired_window_helper() -> None:
    from app.scanners.webapp.probes import _cert_time

    when = _cert_time("Jan  5 10:00:00 2027 GMT")
    assert when == datetime(2027, 1, 5, 10, tzinfo=UTC)
    assert _cert_time("nonsense") is None
    assert timedelta(days=1)  # keep import used
