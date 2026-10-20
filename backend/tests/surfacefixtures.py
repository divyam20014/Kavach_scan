"""Phase 06 fixtures: loopback TCP services, fake DNS with records, project scopes.

All services listen on 127.0.0.1 only; every connection is counted so tests can prove
which ports/hosts were (and were not) touched.
"""

from __future__ import annotations

import socket
import socketserver
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.integrations.dns import DnsRecords
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


def free_port() -> int:
    """A port that is (very likely) closed: bound once, then released."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return int(port)


class BannerServer:
    """TCP service that sends a greeting line and counts connections (no app logic)."""

    def __init__(self, greeting: bytes) -> None:
        self.greeting = greeting
        self.connections = 0
        self.received = b""
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                outer.connections += 1
                try:
                    self.request.sendall(outer.greeting)
                    self.request.settimeout(0.3)
                    try:
                        outer.received += self.request.recv(1024)
                    except OSError:
                        pass
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request: Any, client_address: Any) -> None:
                return

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@dataclass
class RecordsResolver:
    """Fake DNS with A/AAAA/CNAME; records every lookup."""

    table: dict[str, list[str]] = field(default_factory=dict)
    cnames: dict[str, str] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        if host not in self.table:
            raise ResolutionError("NXDOMAIN")
        return list(self.table[host])

    def records(self, host: str) -> DnsRecords:
        addresses = self.resolve(host)
        return DnsRecords(
            host=host,
            a=tuple(a for a in addresses if ":" not in a),
            aaaa=tuple(a for a in addresses if ":" in a),
            cname=self.cnames.get(host),
        )


def surface_dns() -> RecordsResolver:
    return RecordsResolver(
        table={
            "lab.test": ["127.0.0.1"],
            "www.lab.test": ["127.0.0.1"],
            "new.lab.test": ["127.0.0.1"],  # pending approval: resolves, must not be scanned
            "internal.lab.test": ["10.0.0.5"],  # private: blocked by the IP policy
            "meta.lab.test": ["169.254.169.254"],  # cloud metadata: never overridable
            "elsewhere.example": ["127.0.0.1"],  # out of scope: must not even be resolved
        },
        cnames={"www.lab.test": "lab.test"},
    )


def surface_project(ports: list[int], *, hosts: list[str] | None = None, **policy: Any) -> Project:
    now = datetime.now(UTC)
    override = InternalTargetOverride(
        ip_ranges=["127.0.0.1/32"],
        reason="local fixture services for surface tests",
        expires_at=now + timedelta(hours=2),
        audit_event_id=new_id("event"),
    )
    scope = ScopeDefinition(
        schemes=["http", "https"],
        hosts=hosts
        if hosts is not None
        else ["lab.test", "www.lab.test", "internal.lab.test", "meta.lab.test"],
        ports=ports,
        path_prefixes=["/"],
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
        "allowed_modules": ["attack_surface"],
        "requests_per_second": 10,
        "max_concurrency": 2,
    }
    defaults.update(policy)
    return make_project(authorization=auth, scope=scope, scan_policy=ScanPolicy(**defaults))
