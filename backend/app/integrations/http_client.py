"""Pinned HTTP(S) transport: the only code in the application that opens HTTP connections.

Implements `app.scope.Transport`. It is never handed a URL to resolve; it receives an
`AuthorizedTarget` produced by `ScopeGuard` and:

- connects ONLY to one of `authorized.pinned_ips` (no DNS here, so no rebinding window);
  `Host` header and TLS SNI/hostname verification use the canonical hostname;
- never follows redirects (the `GuardedRequester` authorizes each hop separately);
- never uses proxies: there is no proxy code path at all and environment variables such
  as HTTP_PROXY/HTTPS_PROXY/NO_PROXY are not consulted (documented in SCAN_SAFETY.md);
- applies separate connect, read/write (socket) and total-response timeouts;
- caps the body: raw bytes read (`max_response_bytes`) and decoded bytes after gzip/deflate
  (`max_decoded_bytes`); excess is discarded and the response is flagged `truncated`;
  unknown content encodings are not decoded;
- validates request headers (token names, no CR/LF/NUL, no hop-by-hop or framing overrides)
  so caller data can never split a request;
- verifies TLS by default (system trust store, hostname check) and records what the
  client observed in `TlsObservation`. With `verify_tls=False` the handshake proceeds and
  the observation says it was NOT verified;
- sends a fixed, honest User-Agent identifying the assessment tool.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app import __version__ as APP_VERSION
from app.scope.guard import AuthorizedTarget, RequestOptions, TlsObservation, TransportResponse

DEFAULT_USER_AGENT = f"VAPT-Workbench/{APP_VERSION} (authorized security assessment)"
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
_BAD_VALUE = re.compile(r"[\r\n\x00]")
FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-connection",
        "expect",
    }
)
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST"})
MAX_HEADER_VALUE = 8192
_READ_CHUNK = 16384


class TransportError(Exception):
    """The request could not be completed (connect/read failure, timeout, protocol error)."""

    def __init__(self, kind: str, message: str, tls: TlsObservation | None = None) -> None:
        super().__init__(f"{kind}: {message}")
        self.kind = kind  # connect | timeout | tls | protocol | refused
        self.message = message
        self.tls = tls


class HeaderPolicyError(ValueError):
    """A caller-supplied header violates the request header policy (nothing was sent)."""


@dataclass(frozen=True)
class HttpClientConfig:
    connect_timeout: float = 5.0
    read_timeout: float = 15.0  # per socket operation (read and write)
    total_timeout: float = 60.0  # whole exchange, defeats slow-drip responses
    max_response_bytes: int = 1024 * 1024
    max_decoded_bytes: int = 2 * 1024 * 1024
    verify_tls: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    ssl_context_factory: Callable[[bool], ssl.SSLContext] | None = field(default=None, repr=False)

    @classmethod
    def from_policy(cls, policy: Any, *, verify_tls: bool = True) -> HttpClientConfig:
        """Build from a project `ScanPolicy` (timeouts and response cap)."""
        return cls(
            connect_timeout=float(policy.connect_timeout_seconds),
            read_timeout=float(policy.read_timeout_seconds),
            total_timeout=float(policy.read_timeout_seconds) * 4,
            max_response_bytes=int(policy.max_response_bytes),
            max_decoded_bytes=int(policy.max_response_bytes) * 2,
            verify_tls=verify_tls,
        )


def validate_request_headers(headers: tuple[tuple[str, str], ...]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, value in headers:
        if not isinstance(name, str) or not _TOKEN.fullmatch(name):
            raise HeaderPolicyError(f"invalid header name {name!r}")
        if name.lower() in FORBIDDEN_REQUEST_HEADERS:
            raise HeaderPolicyError(f"header {name} may not be set by callers")
        if not isinstance(value, str) or _BAD_VALUE.search(value) or len(value) > MAX_HEADER_VALUE:
            raise HeaderPolicyError(f"invalid value for header {name}")
        out.append((name, value))
    return out


def _default_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _cn(entries: Any) -> str:
    for rdn in entries or ():
        for key, value in rdn:
            if key == "commonName":
                return str(value)[:200]
    return ""


def _observe(sock: ssl.SSLSocket, verified: bool) -> TlsObservation:
    cert: dict[str, Any] = {}
    if verified:
        cert = sock.getpeercert() or {}  # parsed only when the chain was verified
    cipher = sock.cipher()
    return TlsObservation(
        verified=verified,
        version=sock.version() or "",
        cipher=cipher[0] if cipher else "",
        not_before=str(cert.get("notBefore", "")),
        not_after=str(cert.get("notAfter", "")),
        subject_cn=_cn(cert.get("subject")),
        issuer_cn=_cn(cert.get("issuer")),
        san=tuple(str(v) for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address"))[
            :50
        ],
    )


class _PinnedConnection(http.client.HTTPConnection):
    """HTTPConnection whose socket goes to a pre-validated IP; Host stays the hostname."""

    def __init__(self, host: str, port: int, ip: str, config: HttpClientConfig) -> None:
        super().__init__(host, port, timeout=config.read_timeout)
        self._ip = ip
        self._config = config
        self.tls: TlsObservation | None = None

    def _tcp(self) -> socket.socket:
        sock = socket.create_connection((self._ip, self.port), timeout=self._config.connect_timeout)
        sock.settimeout(self._config.read_timeout)
        return sock

    def connect(self) -> None:
        self.sock = self._tcp()


class _PinnedTlsConnection(_PinnedConnection):
    def connect(self) -> None:
        sock = self._tcp()
        factory = self._config.ssl_context_factory or _default_context
        verify = self._config.verify_tls
        context = factory(verify)
        is_ip = _is_ip(self.host)
        try:
            wrapped = context.wrap_socket(
                sock, server_hostname=None if is_ip and not verify else self.host
            )
        except ssl.SSLCertVerificationError as exc:
            sock.close()
            message = exc.verify_message or str(exc)
            raise TransportError(
                "tls",
                f"certificate verification failed: {message}",
                TlsObservation(verified=False, error=str(message)[:300]),
            ) from exc
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            raise TransportError(
                "tls",
                f"TLS handshake failed: {exc}"[:300],
                TlsObservation(verified=False, error=str(exc)[:300]),
            ) from exc
        self.tls = _observe(wrapped, verified=verify)
        self.sock = wrapped


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class _Decoder:
    def __init__(self, encoding: str, limit: int) -> None:
        self.limit = limit
        self.size = 0
        self.truncated = False
        self.chunks: list[bytes] = []
        enc = encoding.strip().lower()
        self.decoded = enc in ("gzip", "x-gzip", "deflate")
        if enc in ("gzip", "x-gzip"):
            self._z: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            self._z = zlib.decompressobj()
        else:
            self._z = None

    def feed(self, data: bytes) -> None:
        if self.truncated:
            return
        if self._z is None:
            out = data
        else:
            try:
                # max_length bounds the output of THIS call: a decompression bomb cannot expand
                # beyond the remaining budget no matter how small the compressed input is.
                out = self._z.decompress(data, max(1, self.limit - self.size + 1))
            except zlib.error:
                self.truncated = True
                return
            if self._z.unconsumed_tail:
                self.truncated = True
        room = self.limit - self.size
        if len(out) > room:
            out = out[:room]
            self.truncated = True
        self.chunks.append(out)
        self.size += len(out)

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


class PinnedHttpTransport:
    """`Transport` implementation over http.client with pinned addresses."""

    def __init__(self, config: HttpClientConfig | None = None) -> None:
        self.config = config or HttpClientConfig()

    def send(
        self, method: str, authorized: AuthorizedTarget, options: RequestOptions | None = None
    ) -> TransportResponse:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise HeaderPolicyError(f"method {method} is not allowed")
        opts = options or RequestOptions()
        extra = validate_request_headers(opts.headers)
        if _BAD_VALUE.search(opts.query) or " " in opts.query or "#" in opts.query:
            raise HeaderPolicyError("query string contains forbidden characters")
        target = authorized.target
        if not authorized.pinned_ips:
            raise TransportError("refused", "no pinned address for target")
        path = target.path + (f"?{opts.query}" if opts.query else "")
        last_error: TransportError | None = None
        for ip in authorized.pinned_ips:  # every pinned address already passed the guard
            try:
                return self._exchange(method, authorized, ip, path, extra, opts.body)
            except TransportError as exc:
                if exc.kind != "connect":
                    raise
                last_error = exc
        assert last_error is not None  # noqa: S101 - loop ran at least once
        raise last_error

    def _exchange(
        self,
        method: str,
        authorized: AuthorizedTarget,
        ip: str,
        path: str,
        extra: list[tuple[str, str]],
        body: bytes | None,
    ) -> TransportResponse:
        target = authorized.target
        cls = _PinnedTlsConnection if target.scheme == "https" else _PinnedConnection
        conn = cls(target.host, target.port, ip, self.config)
        started = time.monotonic()
        try:
            try:
                conn.connect()
            except TransportError:
                raise
            except (TimeoutError, OSError) as exc:
                raise TransportError("connect", f"could not connect to {ip}: {exc}"[:300]) from exc
            conn.putrequest(method, path, skip_host=False, skip_accept_encoding=True)
            names = {n.lower() for n, _ in extra}
            defaults = [
                ("User-Agent", self.config.user_agent),
                ("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"),
                ("Accept-Encoding", "gzip, deflate"),
            ]
            for name, value in defaults:
                if name.lower() not in names:
                    conn.putheader(name, value)
            for name, value in extra:
                conn.putheader(name, value)
            conn.putheader("Connection", "close")
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            response = conn.getresponse()
            return self._read(response, conn, ip, started, method, path, target.url)
        except TransportError:
            raise
        except TimeoutError as exc:
            raise TransportError("timeout", f"timed out talking to {target.host}") from exc
        except (http.client.HTTPException, OSError, ValueError) as exc:
            raise TransportError("protocol", f"{type(exc).__name__}: {exc}"[:300]) from exc
        finally:
            conn.close()

    def _read(
        self,
        response: http.client.HTTPResponse,
        conn: _PinnedConnection,
        ip: str,
        started: float,
        method: str,
        path: str,
        base_url: str,
    ) -> TransportResponse:
        headers = tuple((k, v[:MAX_HEADER_VALUE]) for k, v in response.getheaders())
        encoding = response.getheader("Content-Encoding", "") or ""
        decoder = _Decoder(encoding, self.config.max_decoded_bytes)
        raw_read = 0
        truncated = False
        if method != "HEAD":
            while True:
                if time.monotonic() - started > self.config.total_timeout:
                    truncated = True
                    break
                room = self.config.max_response_bytes - raw_read
                if room <= 0:
                    truncated = bool(response.read(1))  # anything left means we cut it
                    break
                chunk = response.read1(min(_READ_CHUNK, room))  # returns what has arrived
                if not chunk:
                    break
                raw_read += len(chunk)
                decoder.feed(chunk)
                if decoder.truncated:
                    truncated = True
                    break
        query = path.partition("?")[2]
        return TransportResponse(
            status=response.status,
            location=response.getheader("Location"),
            body=decoder.data,
            headers=headers,
            reason=(response.reason or "")[:200],
            truncated=truncated,
            bytes_read=raw_read,
            peer_ip=ip,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            tls=conn.tls,
            url=base_url + (f"?{query}" if query else ""),
        )


def default_transport_factory(config: HttpClientConfig) -> PinnedHttpTransport:
    """Factory handed to scanners so they never construct transports themselves."""
    return PinnedHttpTransport(config)
