"""Minimal runtime configuration (Phase 00).

Phase 01 replaces this with full typed settings and data-root resolution.
Only bind settings live here; the app refuses to bind to non-loopback
addresses because remote secure mode (TBD-003) does not exist yet.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
PRODUCT_NAME = "VAPT Workbench"  # interim name, see TBD-004


class InsecureBindError(ValueError):
    """Raised when a non-loopback bind is requested without a secure mode."""


@dataclass(frozen=True)
class BindConfig:
    host: str
    port: int


def is_loopback_ip(value: str) -> bool:
    """True only for a literal loopback IP address (no name resolution)."""
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def canonical_bind_host(host: str) -> str:
    """Return a canonical loopback IP literal or raise InsecureBindError.

    `localhost` is mapped to 127.0.0.1 so the bind never depends on the hosts file.
    """
    candidate = host.strip()
    if candidate.lower() == "localhost":
        return DEFAULT_HOST
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if is_loopback_ip(candidate):
        return str(ipaddress.ip_address(candidate))
    raise InsecureBindError(
        f"Refusing to bind to non-loopback host {host!r}. Remote access requires a "
        "secure mode (authentication, CSRF, strict CORS) that is not implemented yet. "
        "See TBD-003."
    )


def load_bind_config(env: dict[str, str] | None = None) -> BindConfig:
    """Read VAPT_HOST / VAPT_PORT and enforce the localhost-only policy."""
    source = os.environ if env is None else env
    host = canonical_bind_host(source.get("VAPT_HOST", DEFAULT_HOST))
    raw_port = source.get("VAPT_PORT", str(DEFAULT_PORT)).strip()
    if not raw_port.isascii() or not raw_port.isdigit():
        raise ValueError(f"VAPT_PORT must be a decimal integer, got {raw_port!r}")
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError(f"VAPT_PORT out of range: {port}")
    return BindConfig(host=host, port=port)
