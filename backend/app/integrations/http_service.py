"""Scanner-facing HTTP request service: the single way scanners send HTTP requests.

Layers (outermost first):
1. `HttpService.fetch`   per-host backoff, retries, redirect handling and reporting
2. `ScopeGuard`          `authorize_request` before the first hop, `authorize_redirect`
                         before every further hop (resolves + validates + pins IPs)
3. budgeted transport    per-target request budget, per-host token bucket, concurrency slot
                         (`JobContext.requester`), counted as `requests_sent`
4. `PinnedHttpTransport` connects only to the pinned IPs; caps, timeouts, TLS

Retry policy (bounded, never used to hammer a target):
- connection failures/timeouts on GET/HEAD/OPTIONS: up to `max_retries` retries with
  exponential backoff (0.5 s, 1 s, ... plus jitter); non-idempotent requests are not retried;
- HTTP 429/503: honour `Retry-After` (seconds or HTTP date) capped at `max_retry_after`,
  otherwise exponential backoff; the host is also put in a backoff window so OTHER requests
  to it wait too; after `max_retries` the 429/503 response is returned as-is;
- TLS failures and scope blocks are never retried.
Every retry consumes request budget, and every wait is interruptible by cancellation.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from app.core.redaction import redact_headers
from app.integrations.http_client import HeaderPolicyError, TransportError
from app.scope.engine import Decision
from app.scope.guard import (
    REDIRECT_STATUSES,
    GuardedRequester,
    RequestOptions,
    ScopeBlocked,
    TlsObservation,
    Transport,
    TransportResponse,
)

IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})
RETRY_STATUSES = frozenset({429, 503})


class ServiceContext(Protocol):
    """The subset of `JobContext` the service needs (lets tests use a light fake)."""

    def requester(
        self, transport: Transport, *, max_redirects: int | None = None
    ) -> GuardedRequester: ...

    def sleep(self, seconds: float) -> None: ...

    def incr(self, counter: str, n: int = 1) -> None: ...

    def emit(self, type_: str, message: str, *, level: Any = "info", **data: Any) -> None: ...


@dataclass
class Hop:
    url: str
    status: int | None
    location: str | None = None


@dataclass
class HttpExchange:
    method: str
    url: str
    hops: list[Hop] = field(default_factory=list)
    response: TransportResponse | None = None
    request_headers: dict[str, str] = field(default_factory=dict)  # redacted
    blocked: Decision | None = None  # the request itself was refused by scope
    redirect_blocked: Decision | None = None  # a redirect destination was refused
    redirect_limit: bool = False
    error_kind: str = ""  # connect | timeout | tls | protocol | refused | policy
    error: str = ""
    tls: TlsObservation | None = None  # also set on TLS failures
    attempts: int = 0

    @property
    def ok(self) -> bool:
        return self.response is not None and not self.error_kind

    @property
    def final_url(self) -> str:
        return self.hops[-1].url if self.hops else self.url

    @property
    def status(self) -> int | None:
        return self.response.status if self.response is not None else None


def retry_after_seconds(value: str | None, *, now: datetime | None = None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


class HttpService:
    def __init__(
        self,
        ctx: ServiceContext,
        transport: Transport,
        *,
        max_redirects: int = 5,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        max_retry_after: float = 30.0,
        default_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.ctx = ctx
        self.transport = transport
        self.max_redirects = max_redirects
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.max_retry_after = max_retry_after
        self.default_headers = default_headers
        self._host_backoff: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ public

    def fetch(
        self,
        method: str,
        url: str,
        *,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes | None = None,
        follow_redirects: bool = True,
    ) -> HttpExchange:
        method = method.upper()
        merged = self.default_headers + headers
        exchange = HttpExchange(
            method=method, url=url, request_headers=redact_headers(list(merged))
        )
        requester = self.ctx.requester(self.transport, max_redirects=self.max_redirects)
        guard = requester.guard
        try:
            authorized = guard.authorize_request(url)
        except ScopeBlocked as blocked:
            exchange.blocked = blocked.decision
            exchange.error_kind, exchange.error = "blocked", blocked.decision.message
            return exchange
        options = RequestOptions(query=urlsplit(url).query, headers=merged, body=body)
        current = authorized.target.url + (f"?{options.query}" if options.query else "")
        for hop_index in range(self.max_redirects + 1):
            response = self._send_with_retry(requester, method, authorized, options, exchange)
            if response is None:
                exchange.hops.append(Hop(current, None))
                return exchange
            exchange.hops.append(Hop(current, response.status, response.location))
            exchange.response = response
            if response.tls is not None:
                exchange.tls = response.tls
            if (
                not follow_redirects
                or response.status not in REDIRECT_STATUSES
                or not response.location
            ):
                return exchange
            if hop_index == self.max_redirects:
                exchange.redirect_limit = True
                return exchange
            try:
                authorized = guard.authorize_redirect(current, response.location)
            except ScopeBlocked as blocked:
                exchange.redirect_blocked = blocked.decision
                self.ctx.incr("redirects_blocked")
                return exchange
            if method not in IDEMPOTENT and response.status in (301, 302, 303):
                method, body = "GET", None
            next_url = urljoin(current, response.location.strip())
            options = RequestOptions(query=urlsplit(next_url).query, headers=merged, body=body)
            current = authorized.target.url + (f"?{options.query}" if options.query else "")
        return exchange

    # ------------------------------------------------------------------ internals

    def _wait_for_host(self, host: str) -> None:
        with self._lock:
            until = self._host_backoff.get(host, 0.0)
        remaining = until - time.monotonic()
        if remaining > 0:
            self.ctx.sleep(remaining)

    def _penalize(self, host: str, seconds: float) -> None:
        with self._lock:
            self._host_backoff[host] = max(
                self._host_backoff.get(host, 0.0), time.monotonic() + seconds
            )

    def _backoff(self, attempt: int) -> float:
        return float(self.backoff_base * (2**attempt) + random.uniform(0, self.backoff_base / 2))  # noqa: S311 - jitter, not crypto

    def _send_with_retry(
        self,
        requester: GuardedRequester,
        method: str,
        authorized: Any,
        options: RequestOptions,
        exchange: HttpExchange,
    ) -> TransportResponse | None:
        host = authorized.target.host
        attempt = 0
        while True:
            self._wait_for_host(host)
            exchange.attempts += 1
            try:
                response = requester.transport.send(method, authorized, options)
            except HeaderPolicyError as exc:
                exchange.error_kind, exchange.error = "policy", str(exc)
                return None
            except TransportError as exc:
                exchange.tls = exc.tls or exchange.tls
                retryable = exc.kind in ("connect", "timeout", "protocol") and method in IDEMPOTENT
                if retryable and attempt < self.max_retries:
                    delay = self._backoff(attempt)
                    attempt += 1
                    self.ctx.incr("request_retries")
                    self.ctx.emit(
                        "http_retry",
                        f"{exc.kind} error on {host}; retry {attempt} in {delay:.1f}s",
                        level="warning",
                    )
                    self._penalize(host, delay)
                    continue
                exchange.error_kind, exchange.error = exc.kind, exc.message
                self.ctx.incr("request_errors")
                return None
            if response.status in RETRY_STATUSES:
                self.ctx.incr("rate_limited_responses")
                hinted = retry_after_seconds(response.header("Retry-After"))
                delay = min(
                    self.max_retry_after,
                    hinted if hinted is not None else self._backoff(attempt),
                )
                self._penalize(host, delay)
                if attempt < self.max_retries:
                    attempt += 1
                    self.ctx.emit(
                        "rate_limited",
                        f"{host} answered {response.status}; backing off {delay:.1f}s "
                        f"(retry {attempt}/{self.max_retries})",
                        level="warning",
                    )
                    continue
                self.ctx.emit(
                    "rate_limited",
                    f"{host} still answered {response.status} after {attempt} retries",
                    level="warning",
                )
            return response
