"""TCP connect adapter: the only code in the application that opens raw TCP connections.

- A connection is opened ONLY to an address in `authorized.pinned_ips` (produced by
  `ScopeGuard.authorize_connect`, which checked host, port and every resolved IP).
- Full TCP connect (no raw sockets, no SYN/stealth techniques, no source spoofing).
- Banner read is passive: after connecting, the adapter waits briefly for the service's
  own greeting (SSH, FTP, SMTP, ...) and NEVER sends any data. At most `max_banner`
  bytes are kept; the connection is then closed.
- States: `open` (connected), `closed` (refused), `filtered` (timeout), `error` (other).
"""

from __future__ import annotations

import socket  # this module is the sanctioned raw-TCP adapter
import time
from dataclasses import dataclass
from typing import Literal

from app.scope.guard import AuthorizedTarget

PortState = Literal["open", "closed", "filtered", "error"]
MAX_BANNER_BYTES = 512


@dataclass(frozen=True)
class PortProbe:
    ip: str
    port: int
    state: PortState
    banner: bytes = b""
    error: str = ""
    elapsed_ms: int = 0


def probe_port(
    authorized: AuthorizedTarget,
    ip: str,
    port: int,
    *,
    connect_timeout: float = 3.0,
    banner_timeout: float = 1.5,
    read_banner: bool = True,
    max_banner: int = MAX_BANNER_BYTES,
) -> PortProbe:
    if ip not in authorized.pinned_ips:
        raise ValueError("refusing to connect to an address that the scope guard did not pin")
    if authorized.target.port != port:
        raise ValueError("port does not match the authorized target")
    started = time.monotonic()

    def done(state: PortState, banner: bytes = b"", error: str = "") -> PortProbe:
        return PortProbe(ip, port, state, banner, error, int((time.monotonic() - started) * 1000))

    try:
        sock = socket.create_connection((ip, port), timeout=connect_timeout)
    except ConnectionRefusedError:
        return done("closed")
    except TimeoutError:
        return done("filtered")
    except OSError as exc:
        return done("error", error=f"{type(exc).__name__}: {exc}"[:200])
    banner = b""
    try:
        if read_banner and banner_timeout > 0:
            sock.settimeout(banner_timeout)
            deadline = time.monotonic() + banner_timeout
            while len(banner) < max_banner and time.monotonic() < deadline:
                try:
                    chunk = sock.recv(max_banner - len(banner))
                except (TimeoutError, OSError):
                    break
                if not chunk:
                    break
                banner += chunk
                if b"\n" in chunk:
                    break  # a greeting line is enough
    finally:
        sock.close()
    return done("open", banner[:max_banner])
