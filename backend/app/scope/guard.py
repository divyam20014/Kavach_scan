"""The policy hook every outbound action must pass (MASTER_SPEC §4.2, Module 3).

`ScopeGuard` is the ONLY sanctioned way for future HTTP, DNS, port-probe and subprocess
code to obtain permission to touch a target. It:

1. checks the global kill switch and the project's authorization window (every call,
   so a scan crossing the window end stops);
2. canonicalizes and statically checks scheme/host/port/path against the scope;
3. resolves the host through an *injected* resolver and validates EVERY address;
4. returns an `AuthorizedTarget` whose `pinned_ips` are the only addresses a transport
   may connect to (defeats DNS rebinding between check and use);
5. records every allow/block `Decision` to a sink (job events, audit, tests).

Nothing here performs network I/O. The real resolver (`app/integrations/dns.py`) and
transport (`app/integrations/http_client.py`) are wired through this class.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from app.models.common import ScopeStatus, utc_now
from app.models.project import Project
from app.scope.canonical import (
    CanonicalizationError,
    CanonicalTarget,
    normalize_host,
    normalize_target,
)
from app.scope.engine import Decision, Reason, ScopePolicy

MAX_REDIRECTS_HARD_CAP = 10


class ResolutionError(Exception):
    """The resolver could not resolve a name."""


class Resolver(Protocol):
    def resolve(self, host: str) -> list[str]:
        """Return the IP address strings `host` resolves to (A and AAAA)."""


class DecisionSink(Protocol):
    def record(self, decision: Decision) -> None: ...


class ScopeBlocked(Exception):
    """Raised when a guarded action is denied. Carries the auditable decision."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"{decision.reason.value}: {decision.message}")
        self.decision = decision


@dataclass
class MemorySink:
    decisions: list[Decision] = field(default_factory=list)

    def record(self, decision: Decision) -> None:
        self.decisions.append(decision)

    @property
    def blocked(self) -> list[Decision]:
        return [d for d in self.decisions if not d.allowed]


@dataclass(frozen=True)
class AuthorizedTarget:
    target: CanonicalTarget
    pinned_ips: tuple[str, ...]  # connect ONLY to these; send Host/SNI = target.host
    decisions: tuple[Decision, ...]


class ScopeGuard:
    def __init__(
        self,
        project: Project,
        *,
        resolver: Resolver,
        sink: DecisionSink,
        clock: Callable[[], datetime] = utc_now,
        kill_switch: Callable[[], bool] = lambda: False,
    ) -> None:
        self.policy = ScopePolicy(project, clock=clock)
        self.resolver = resolver
        self.sink = sink
        self.kill_switch = kill_switch

    # ------------------------------------------------------------------ internals

    def _emit(self, decision: Decision) -> Decision:
        self.sink.record(decision)
        return decision

    def _deny(self, decision: Decision) -> ScopeBlocked:
        self._emit(decision)
        return ScopeBlocked(decision)

    def _gate(self, what: str) -> None:
        if self.kill_switch():
            raise self._deny(
                self.policy._decision(
                    False,
                    Reason.KILL_SWITCH,
                    "Global kill switch is engaged",
                    "kill_switch",
                    input=what,
                )
            )
        auth = self.policy.authorization()
        if not auth.allowed:
            raise self._deny(auth.model_copy(update={"input": what[:500]}))

    def _resolve_and_pin(
        self, host: str, literal: str | None, label: str
    ) -> tuple[tuple[str, ...], list[Decision]]:
        if literal is not None:
            decision = self.policy.validate_resolved_ip(host, literal)
            if not decision.allowed:
                raise self._deny(decision)
            return (literal,), [self._emit(decision)]
        try:
            addresses = self.resolver.resolve(host)
        except ResolutionError as exc:
            raise self._deny(
                self.policy._decision(
                    False,
                    Reason.RESOLUTION_FAILED,
                    f"could not resolve {host}: {exc}"[:480],
                    "resolved_ip",
                    input=label,
                    target=host,
                )
            ) from exc
        if not addresses:
            raise self._deny(
                self.policy._decision(
                    False,
                    Reason.NO_ADDRESSES,
                    f"{host} has no addresses",
                    "resolved_ip",
                    input=label,
                    target=host,
                )
            )
        decisions: list[Decision] = []
        for address in addresses:  # ALL answers must pass; one bad answer blocks the action
            decision = self.policy.validate_resolved_ip(host, address)
            if not decision.allowed:
                raise self._deny(decision)
            decisions.append(self._emit(decision))
        return tuple(dict.fromkeys(d.ip for d in decisions if d.ip)), decisions

    # ------------------------------------------------------------------ entry points

    def authorize_request(self, url: str) -> AuthorizedTarget:
        """Gate an HTTP(S) request. Raise ScopeBlocked unless every check passes."""
        self._gate(url)
        static = self.policy.is_target_in_scope(url)
        if not static.allowed:
            raise self._deny(static)
        self._emit(static)
        target = normalize_target(url)
        pinned, ip_decisions = self._resolve_and_pin(
            target.host, str(target.ip) if target.ip else None, url
        )
        return AuthorizedTarget(target=target, pinned_ips=pinned, decisions=(static, *ip_decisions))

    def authorize_redirect(self, current_url: str, location: str) -> AuthorizedTarget:
        """Gate following a redirect. The destination is re-checked from scratch."""
        self._gate(location)
        decision = self.policy.validate_redirect(current_url, location)
        if not decision.allowed:
            raise self._deny(decision)
        self._emit(decision)
        assert decision.target is not None  # noqa: S101 - allowed decisions always carry a target
        target = normalize_target(decision.target)
        pinned, ip_decisions = self._resolve_and_pin(
            target.host, str(target.ip) if target.ip else None, location
        )
        return AuthorizedTarget(
            target=target, pinned_ips=pinned, decisions=(decision, *ip_decisions)
        )

    def authorize_connect(self, host: str, port: int) -> AuthorizedTarget:
        """Gate a raw TCP connection (port checks, banner grabs)."""
        label = f"{host}:{port}"
        self._gate(label)
        try:
            canonical, ip = normalize_host(host)
        except CanonicalizationError as exc:
            reason = (
                Reason(exc.code) if exc.code in {r.value for r in Reason} else Reason.INVALID_HOST
            )
            raise self._deny(
                self.policy._decision(False, reason, exc.message, "connect", input=label)
            ) from exc
        static = self.policy.is_host_port_allowed(host, port, input=label)
        if not static.allowed:
            raise self._deny(static)
        self._emit(static)
        scheme = "https" if "https" in self.policy.schemes else "http"
        target = CanonicalTarget(scheme=scheme, host=canonical, ip=ip, port=port, path="/")
        pinned, ip_decisions = self._resolve_and_pin(canonical, str(ip) if ip else None, label)
        return AuthorizedTarget(target=target, pinned_ips=pinned, decisions=(static, *ip_decisions))

    def classify_discovered_host(self, host: str) -> tuple[ScopeStatus, Decision]:
        """Classify a host found during discovery. Resolution success never implies approval."""
        try:
            canonical, ip = normalize_host(host)
        except CanonicalizationError as exc:
            d = self.policy._decision(
                False, Reason.INVALID_HOST, exc.message, "discovered_host", input=host
            )
            return ScopeStatus.OUT_OF_SCOPE, self._emit(d)
        if ip is not None:
            in_range = any(ip.version == n.version and ip in n for n in self.policy.networks)
            status = ScopeStatus.IN_SCOPE if in_range else ScopeStatus.OUT_OF_SCOPE
            rule = "ip_range" if in_range else None
        else:
            status, rule = self.policy.host_status(canonical)
        allowed = status == ScopeStatus.IN_SCOPE
        reason = (
            Reason.ALLOWED
            if allowed
            else (
                Reason.HOST_EXCLUDED if status == ScopeStatus.EXCLUDED else Reason.HOST_OUT_OF_SCOPE
            )
        )
        d = self.policy._decision(
            allowed,
            reason,
            f"discovered host is {status.value}",
            "discovered_host",
            input=host,
            target=canonical,
            rule=rule,
        )
        return status, self._emit(d)

    def authorize_subprocess_targets(
        self, hosts: list[str], ports: list[int]
    ) -> list[AuthorizedTarget]:
        """Gate an external tool invocation: every host/port it will touch must be authorized."""
        return [self.authorize_connect(h, p) for h in hosts for p in ports]


# ---------------------------------------------------------------------- guarded request adapter


@dataclass(frozen=True)
class RequestOptions:
    """Per-request extras. The query string travels separately because scope is path-based."""

    query: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None


@dataclass(frozen=True)
class TlsObservation:
    """What the client saw during the TLS handshake (no third-party parsing)."""

    verified: bool
    version: str = ""
    cipher: str = ""
    error: str = ""  # verification failure text when not verified
    not_before: str = ""
    not_after: str = ""
    subject_cn: str = ""
    issuer_cn: str = ""
    san: tuple[str, ...] = ()


@dataclass(frozen=True)
class TransportResponse:
    status: int
    location: str | None = None
    body: bytes = b""
    headers: tuple[tuple[str, str], ...] = ()  # in received order; duplicates preserved
    reason: str = ""
    truncated: bool = False  # body cut at the byte or decompression cap
    bytes_read: int = 0  # raw bytes read from the wire for the body
    peer_ip: str | None = None
    elapsed_ms: int = 0
    tls: TlsObservation | None = None
    url: str = ""  # the canonical URL (with query) this response belongs to

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self.headers if k.lower() == lowered]


class Transport(Protocol):
    """A raw transport. It must connect only to `authorized.pinned_ips` and never resolve DNS."""

    def send(
        self, method: str, authorized: AuthorizedTarget, options: RequestOptions | None = None
    ) -> TransportResponse: ...


REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _query_of(url: str) -> str:
    return urlsplit(url).query


class GuardedRequester:
    """Wraps a raw transport so that nothing reaches it without a passing guard decision.

    Scanners use this class (never the transport directly). Each hop is authorized
    separately: the first via `authorize_request`, every redirect via `authorize_redirect`
    (which resolves and validates the destination from scratch). Redirects are never
    followed by the transport itself.
    """

    def __init__(self, guard: ScopeGuard, transport: Transport, *, max_redirects: int = 5) -> None:
        self.guard = guard
        self.transport = transport
        self.max_redirects = min(max_redirects, MAX_REDIRECTS_HARD_CAP)

    def request(
        self,
        method: str,
        url: str,
        options: RequestOptions | None = None,
        *,
        follow_redirects: bool = True,
    ) -> tuple[TransportResponse, list[str]]:
        """Return (final response, chain of canonical URLs requested, query included)."""
        authorized = self.guard.authorize_request(url)
        opts = options or RequestOptions(query=_query_of(url))
        chain: list[str] = []
        for _ in range(self.max_redirects + 1):
            response = self.transport.send(method, authorized, opts)
            current = authorized.target.url + (f"?{opts.query}" if opts.query else "")
            chain.append(current)
            if (
                not follow_redirects
                or response.status not in REDIRECT_STATUSES
                or not response.location
            ):
                return response, chain
            authorized = self.guard.authorize_redirect(current, response.location)
            # 301/302/303 after a non-GET become GET without a body (as browsers do).
            if method not in ("GET", "HEAD") and response.status in (301, 302, 303):
                method = "GET"
            next_url = urljoin(current, response.location.strip())
            opts = RequestOptions(
                query=_query_of(next_url),
                headers=opts.headers,
                body=opts.body if method not in ("GET", "HEAD") else None,
            )
        raise self.guard._deny(
            self.guard.policy._decision(
                False,
                Reason.REDIRECT_LIMIT,
                f"more than {self.max_redirects} redirects",
                "redirect",
                input=url,
            )
        )
