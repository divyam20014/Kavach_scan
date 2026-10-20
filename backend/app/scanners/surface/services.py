"""Simple service identification from port numbers and passively read banners.

Banners are untrusted bytes: decoded as Latin-1, reduced to printable characters,
whitespace-collapsed, passed through the secret redactor and capped. Nothing is ever sent
to the service, and no login is attempted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.redaction import redact_text
from app.scanners.surface.rules import ADMIN_PORTS, CLEARTEXT_PORTS, DATABASE_PORTS

MAX_BANNER_CHARS = 200
PORT_NAMES = {
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    8000: "http",
    8080: "http-alt",
    8443: "https-alt",
    **DATABASE_PORTS,
    **ADMIN_PORTS,
    **CLEARTEXT_PORTS,
}
_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    # (pattern with optional version group, service, product)
    (re.compile(r"^SSH-[\d.]+-OpenSSH_([\w.]+)"), "ssh", "OpenSSH"),
    (re.compile(r"^SSH-[\d.]+-dropbear_([\w.]+)"), "ssh", "Dropbear"),
    (re.compile(r"^SSH-[\d.]+-(\S+)"), "ssh", ""),
    (re.compile(r"^220.*\(vsFTPd ([\d.]+)\)", re.I), "ftp", "vsftpd"),
    (re.compile(r"^220.*ProFTPD ([\d.]+)", re.I), "ftp", "ProFTPD"),
    (re.compile(r"^220.*FileZilla Server ([\d.]+)?", re.I), "ftp", "FileZilla Server"),
    (re.compile(r"^220.*ESMTP Postfix"), "smtp", "Postfix"),
    (re.compile(r"^220.*Exim ([\d.]+)", re.I), "smtp", "Exim"),
    (re.compile(r"^220.*Microsoft ESMTP MAIL Service"), "smtp", "Microsoft Exchange"),
    (re.compile(r"^220[ -].*SMTP", re.I), "smtp", ""),
    (re.compile(r"^220[ -].*FTP", re.I), "ftp", ""),
    (re.compile(r"^\+OK"), "pop3", ""),
    (re.compile(r"^\* OK.*IMAP", re.I), "imap", ""),
    (re.compile(r"^HTTP/\d"), "http", ""),
    (re.compile(r"(\d+\.\d+\.\d+)[-\w]*.*mysql_native_password", re.I), "mysql", "MySQL/MariaDB"),
]


@dataclass(frozen=True)
class ServiceInfo:
    service: str
    product: str = ""
    version: str = ""
    banner: str = ""
    source: str = "port"  # port | banner


def sanitize_banner(raw: bytes) -> str:
    text = raw[:1024].decode("latin-1")
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    collapsed = " ".join(printable.split())
    return redact_text(collapsed, max_chars=MAX_BANNER_CHARS)


def identify(port: int, banner: str) -> ServiceInfo:
    for pattern, service, product in _SIGNATURES:
        m = pattern.search(banner)
        if m:
            version = m.group(1) if m.groups() and m.group(1) else ""
            if not product and service == "ssh":
                product, version = version, ""
            return ServiceInfo(service, product, version[:40], banner, "banner")
    return ServiceInfo(PORT_NAMES.get(port, "unknown"), "", "", banner, "port")
