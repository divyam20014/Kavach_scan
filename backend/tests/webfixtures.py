"""Local fixture web apps for Phase 05 (loopback only; every request is logged).

LAB     the authorized target app (`lab.test`), with pages that demonstrate each check:
        missing headers, cookies, version banners, directory listing, default page,
        debug traceback, database error text, escaped/unescaped reflection of a value
        already present in a crawled link, an off-scope redirect, a robots-disallowed
        area, an excluded path, a crawler trap, a rate-limited page and a CORS reflector.
VICTIM  a server that must NEVER receive a request (off-scope redirect destination).

`TlsLab` serves HTTPS with certificates generated at runtime (valid / expired /
wrong-hostname), signed by a throwaway test CA; no key material is committed.
"""

from __future__ import annotations

import gzip
import html
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

from app.models import new_id
from app.models.project import (
    AuthorizationRecord,
    InternalTargetOverride,
    Project,
    ScanPolicy,
    ScopeDefinition,
)
from app.scope.guard import ResolutionError
from tests.conftest import make_project

SESSION_SECRET = "s3ss10n-v4lue-n3ver-st0red"  # noqa: S105 - fixture value that must never be stored


@dataclass
class Hit:
    path: str
    headers: dict[str, str]
    method: str = "GET"


class _Logged(BaseHTTPRequestHandler):
    hits: ClassVar[list[Hit]] = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a: object) -> None:
        return

    def _record(self) -> None:
        type(self).hits.append(
            Hit(self.path, {k.lower(): v for k, v in self.headers.items()}, self.command)
        )

    def _send(
        self,
        status: int,
        body: bytes,
        headers: list[tuple[str, str]] | None = None,
        ctype: str = "text/html; charset=utf-8",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in headers or []:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class VictimHandler(_Logged):
    hits: ClassVar[list[Hit]] = []

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        self._send(200, b"internal secret")


def _page(title: str, body: str) -> bytes:
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>".encode()


class LabHandler(_Logged):
    hits: ClassVar[list[Hit]] = []
    victim_port: ClassVar[int] = 0
    rate_limited_once: ClassVar[set[str]] = set()
    delay: ClassVar[float] = 0.0

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._record()
        # Deliberately advertises TRACE so WEB-METHOD-001's finding path is exercised
        # end to end; nothing here ever sends a TRACE request itself.
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        if type(self).delay:
            time.sleep(type(self).delay)
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        cls = type(self)
        banner = [("Server", "Apache/2.4.41 (Ubuntu)"), ("X-Powered-By", "PHP/7.4.3")]
        origin = self.headers.get("Origin")
        cors = (
            [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            if origin
            else []
        )
        if path == "/":
            body = (
                '<meta name="generator" content="WordPress 6.4.2">'
                '<script src="/static/jquery-3.5.1.min.js"></script>'
                '<a href="/about">About</a> <a href="/listing/">Files</a> '
                '<a href="/default">Default</a> <a href="/error">Error</a> '
                '<a href="/dberror?id=1">Item</a> '
                '<a href="/echo?msg=%3Cb%3Ehello%3C%2Fb%3E">Echo</a> '
                '<a href="/echo-safe?msg=%3Ci%3Esafe%3C%2Fi%3E">Safe echo</a> '
                f'<a href="/go?next=http%3A%2F%2Fvictim.test%3A{cls.victim_port}%2Fsteal">Go</a> '
                '<a href="/admin/">Admin</a> <a href="/private/keys">Private</a> '
                '<a href="/loop/a/">Loop</a> <a href="/limited">Limited</a> '
                '<a href="http://outside.example/x">Elsewhere</a> '
                '<a href="mailto:x@example.com">Mail</a> <a href="/report.pdf">PDF</a> '
                '<a href="/#frag">Self</a>'
                '<form action="/login" method="post"><input name="user">'
                '<input type="password" name="pw"></form>'
            )
            self._send(
                200,
                _page("Lab home", body),
                banner
                + cors
                + [
                    ("Set-Cookie", f"PHPSESSID={SESSION_SECRET}; Path=/"),
                ],
            )
        elif path == "/about":
            self._send(
                200,
                _page("About", '<a href="/">Home</a>'),
                [
                    (
                        "Content-Security-Policy",
                        "default-src 'self'; script-src 'self' 'unsafe-inline'",
                    ),
                    ("X-Content-Type-Options", "nosniff"),
                    ("X-Frame-Options", "DENY"),
                    ("Referrer-Policy", "no-referrer"),
                    ("Permissions-Policy", "camera=()"),
                ],
            )
        elif path == "/listing/":
            self._send(
                200,
                _page(
                    "Index of /listing",
                    '<h1>Index of /listing</h1><a href="../">Parent Directory</a>',
                ),
            )
        elif path == "/default":
            self._send(
                200,
                b"<html><head><title>Welcome to nginx!</title></head>"
                b"<body><h1>Welcome to nginx!</h1></body></html>",
            )
        elif path == "/error":
            self._send(
                500,
                _page(
                    "Error",
                    "<pre>Traceback (most recent call last):\n"
                    '  File "app.py", line 1\nValueError: boom</pre>',
                ),
            )
        elif path == "/dberror":
            self._send(
                200,
                _page(
                    "Item",
                    "Warning: You have an error in your SQL syntax; check the manual near ''",
                ),
            )
        elif path == "/echo":
            self._send(200, _page("Echo", f"<p>You said: {query.get('msg', [''])[0]}</p>"))
        elif path == "/echo-safe":
            self._send(
                200, _page("Echo", f"<p>You said: {html.escape(query.get('msg', [''])[0])}</p>")
            )
        elif path == "/go":
            self.send_response(302)
            self.send_header("Location", query.get("next", ["/"])[0])
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", ctype="text/plain")
        elif path.startswith("/loop/"):
            self._send(200, _page("Loop", f'<a href="{path}a/">deeper</a>'))
        elif path == "/limited":
            if path not in cls.rate_limited_once:
                cls.rate_limited_once.add(path)
                self._send(429, b"slow down", [("Retry-After", "1")], ctype="text/plain")
            else:
                self._send(200, _page("Limited", "ok now"))
        elif path == "/big":
            self._send(200, b"x" * (3 * 1024 * 1024), ctype="text/plain")
        elif path == "/bomb":
            payload = gzip.compress(b"\0" * (40 * 1024 * 1024))
            self._send(200, payload, [("Content-Encoding", "gzip")], ctype="text/plain")
        elif path == "/slow":
            time.sleep(2.0)
            self._send(200, b"late", ctype="text/plain")
        elif path == "/drip":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.05)
        elif path == "/echo-headers":
            names = ",".join(sorted(self.headers.keys()))
            self._send(
                200, f"host={self.headers.get('Host')};names={names}".encode(), ctype="text/plain"
            )
        elif path == "/unavailable":
            self._send(503, b"maintenance", [("Retry-After", "25")], ctype="text/plain")
        elif path == "/flaky":
            if path not in cls.rate_limited_once:
                cls.rate_limited_once.add(path)
                self._send(503, b"busy", [("Retry-After", "1")], ctype="text/plain")
            else:
                self._send(200, _page("Flaky", "recovered"))
        elif path == "/text":
            self._send(200, b'<a href="/from-plain-text">not html</a>', ctype="text/plain")
        elif path == "/to-private":
            self.send_response(302)
            self.send_header("Location", "/private/keys")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/redirect-same":
            self.send_response(301)
            self.send_header("Location", "/about")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(404, _page("Not found", "nothing here"))


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        return  # clients aborting on purpose (timeouts, caps) are expected in these tests


def start_server(
    handler: type[BaseHTTPRequestHandler], tls: ssl.SSLContext | None = None
) -> ThreadingHTTPServer:
    server = _QuietServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@contextmanager
def lab_servers() -> Iterator[tuple[int, int]]:
    LabHandler.hits = []
    VictimHandler.hits = []
    LabHandler.rate_limited_once = set()
    LabHandler.delay = 0.0
    lab = start_server(LabHandler)
    victim = start_server(VictimHandler)
    LabHandler.victim_port = victim.server_address[1]
    try:
        yield lab.server_address[1], victim.server_address[1]
    finally:
        for s in (lab, victim):
            s.shutdown()
            s.server_close()


@dataclass
class MapResolver:
    """Fixture resolver: hostnames → addresses (default lab.test/victim.test → loopback)."""

    table: dict[str, list[str]] = field(
        default_factory=lambda: {"lab.test": ["127.0.0.1"], "victim.test": ["127.0.0.1"]}
    )
    calls: list[str] = field(default_factory=list)

    def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        if host not in self.table:
            raise ResolutionError("NXDOMAIN")
        return list(self.table[host])


def lab_project(ports: list[int], *, schemes: list[str] | None = None, **policy: Any) -> Project:
    now = datetime.now(UTC)
    override = InternalTargetOverride(
        ip_ranges=["127.0.0.1/32"],
        reason="local fixture lab for the web scanner tests",
        expires_at=now + timedelta(hours=2),
        audit_event_id=new_id("event"),
    )
    scope = ScopeDefinition(
        schemes=schemes or ["http"],  # type: ignore[arg-type]
        hosts=["lab.test"],
        ports=ports,
        path_prefixes=["/"],
        exclusions={"path_prefixes": ["/private"]},  # type: ignore[arg-type]
        internal_override=override,
    )
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=1),
        attestation_event_id=new_id("event"),
    )
    defaults: dict[str, Any] = {
        "allowed_modules": ["web_app"],
        "requests_per_second": 10,
        "max_concurrency": 2,
        # Wider than `ScanPolicy`'s own production defaults (5s/15s) on purpose: these
        # fixture requests are real loopback HTTP calls serviced by a thread in the SAME
        # test process as the job worker consuming them, so they compete for the same GIL
        # and CPU as the rest of the suite -- under real system load (confirmed directly:
        # a concurrent frontend test run starved even the frontend's own worker pool, unable
        # to start 7 of its own workers in time) a connect/read that would be instant in
        # isolation can occasionally take longer than production's own tight budget allows.
        # A real investigation (two full-suite reproduction attempts, one of them under
        # confirmed heavy concurrent contention) could not reproduce the historical
        # intermittent failure directly, so this margin is a disclosed, deliberate
        # mitigation for a suspected rare race, not a confirmed fix for a confirmed cause --
        # see TBD_DECISIONS.md. Individual tests that need a short timeout to exercise
        # timeout/backoff behavior build their own `HttpClientConfig` directly and are
        # unaffected by this default.
        "connect_timeout_seconds": 20.0,
        "read_timeout_seconds": 40.0,
    }
    defaults.update(policy)
    return make_project(authorization=auth, scope=scope, scan_policy=ScanPolicy(**defaults))


# ---------------------------------------------------------------------- TLS fixtures


@dataclass
class TestPki:
    ca_pem: bytes
    certs: dict[str, tuple[Path, Path]]  # kind -> (cert file, key file)

    def client_context(self, verify: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cadata=self.ca_pem.decode())
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


def make_pki(directory: Path) -> TestPki:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VAPT Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    specs = {
        "valid": ("lab.test", now - timedelta(days=1), now + timedelta(days=90)),
        "expired": ("lab.test", now - timedelta(days=60), now - timedelta(days=1)),
        "wronghost": ("other.test", now - timedelta(days=1), now + timedelta(days=90)),
        "expiring": ("lab.test", now - timedelta(days=1), now + timedelta(days=5)),
    }
    certs: dict[str, tuple[Path, Path]] = {}
    for kind, (host, start, end) in specs.items():
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_path, key_path = directory / f"{kind}.crt", directory / f"{kind}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        certs[kind] = (cert_path, key_path)
    return TestPki(ca.public_bytes(serialization.Encoding.PEM), certs)


def server_context(pki: TestPki, kind: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert, key = pki.certs[kind]
    ctx.load_cert_chain(cert, key)
    return ctx
