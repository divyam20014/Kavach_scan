"""Canonicalization of targets. Anything ambiguous is rejected rather than guessed.

The rules exist because HTTP clients, proxies and servers disagree about edge cases;
an input that two components could interpret differently is refused. Examples:
`http://trusted@evil` (user-info), `http://evil\\@trusted` (backslash), `127.1` /
`0x7f.0.0.1` / `2130706433` (numeric shorthand that resolves to loopback),
`/api/%2e%2e/admin` (encoded traversal), `/api/%252e%252e/` (double encoding),
`/api/..;/admin` (path-parameter traversal), `fe80::1%eth0` (zone IDs).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.scope.ip_policy import IPAddress

DEFAULT_PORTS = {"http": 80, "https": 443}
WEB_SCHEMES = frozenset(DEFAULT_PORTS)
MAX_URL_LENGTH = 4096

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_UNRESERVED = re.compile(r"[A-Za-z0-9\-._~]")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x20\x7f\\]")


class CanonicalizationError(ValueError):
    """Input could not be canonicalized safely. `code` is a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class CanonicalTarget:
    scheme: str
    host: str  # punycode hostname or canonical IP text (no brackets)
    ip: IPAddress | None  # set when the host is an IP literal
    port: int  # explicit or scheme default
    path: str  # normalized, always starts with "/"

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if self.ip is not None and self.ip.version == 6 else self.host
        default = DEFAULT_PORTS.get(self.scheme)
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{host}{port}{self.path}"

    @property
    def origin(self) -> str:
        return self.url[: len(self.url) - len(self.path)]


def parse_ip(text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def normalize_hostname(raw: str) -> str:
    """IDNA -> punycode, lowercase, strip one trailing dot, validate labels.

    Rejects numeric shorthand that resolvers/browsers would treat as an IP address.
    """
    host = raw.strip()
    if not host or _FORBIDDEN_CHARS.search(host) or "%" in host:
        raise CanonicalizationError("invalid_host", "hostname contains forbidden characters")
    if host.endswith("."):
        host = host[:-1]
    try:
        # Python's IDNA codec also maps ideographic/fullwidth full stops to "."
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CanonicalizationError("invalid_host", "hostname is not valid IDNA") from exc
    if len(host) > 253 or not _HOST_RE.fullmatch(host):
        raise CanonicalizationError("invalid_host", "not a valid DNS hostname")
    labels = host.split(".")
    if all(_NUMERIC_LABEL.fullmatch(label) for label in labels) or _NUMERIC_LABEL.fullmatch(
        labels[-1]
    ):
        # "127.1", "0x7f.1", "2130706433", "1.2.3.04" — would be parsed as an IP by many clients
        raise CanonicalizationError("ambiguous_host", "numeric host is not a canonical IP address")
    return host


def normalize_host(raw: str) -> tuple[str, IPAddress | None]:
    """Return (canonical host text, ip-or-None). Accepts bracketed IPv6."""
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
        if "%" in text:
            raise CanonicalizationError("ambiguous_host", "IPv6 zone identifiers are not allowed")
        ip = parse_ip(text)
        if ip is None or ip.version != 6:
            raise CanonicalizationError("invalid_host", "invalid bracketed IPv6 address")
        return str(ip), ip
    if "%" in text:
        raise CanonicalizationError(
            "ambiguous_host", "percent-encoding or zone IDs are not allowed in hosts"
        )
    ip = parse_ip(text)
    if ip is not None:
        if ip.version == 4 and str(ip) != text:  # leading zeros etc.
            raise CanonicalizationError(
                "ambiguous_host", "IPv4 address is not in canonical dotted form"
            )
        return str(ip), ip
    return normalize_hostname(text), None


def normalize_path(raw: str) -> str:
    """Percent-decode unreserved characters once, remove dot segments, reject ambiguity."""
    path = raw or "/"
    if not path.startswith("/"):
        raise CanonicalizationError("ambiguous_path", "path must start with '/'")
    if _FORBIDDEN_CHARS.search(path):
        raise CanonicalizationError(
            "ambiguous_path", "path contains whitespace, control characters or backslashes"
        )

    def decode(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if _UNRESERVED.fullmatch(char) else "%" + match.group(1).upper()

    decoded = _PCT.sub(decode, path)
    lowered = decoded.lower()
    if any(enc in lowered for enc in ("%2f", "%5c", "%00", "%25")):
        # encoded separators/NUL, or double encoding ("%252e") a later decode could turn into ".."
        raise CanonicalizationError(
            "ambiguous_path", "encoded separators or double encoding are not allowed"
        )
    segments = decoded.split("/")
    out: list[str] = []
    for segment in segments[1:]:
        if segment.startswith((".;", "..;")):
            raise CanonicalizationError(
                "ambiguous_path", "dot segments with path parameters are not allowed"
            )
        if segment == ".":
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    normalized = "/" + "/".join(out)
    if decoded.endswith(("/.", "/..")) and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def normalize_port(value: int | str | None, scheme: str) -> int:
    if value is None or value == "":
        return DEFAULT_PORTS[scheme]
    if isinstance(value, str):
        if not value.isascii() or not value.isdigit():
            raise CanonicalizationError("invalid_port", "port must be a decimal integer")
        value = int(value)
    if not 1 <= value <= 65535:
        raise CanonicalizationError("invalid_port", "port must be between 1 and 65535")
    return value


def normalize_target(url: str) -> CanonicalTarget:
    """Canonicalize an absolute http(s) URL. Query and fragment are not part of scope."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise CanonicalizationError("unparseable", "URL is empty or too long")
    if _FORBIDDEN_CHARS.search(url):
        raise CanonicalizationError(
            "unparseable", "URL contains whitespace, control characters or backslashes"
        )
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise CanonicalizationError("unparseable", "URL could not be parsed") from exc
    scheme = parts.scheme.lower()
    if scheme not in WEB_SCHEMES:
        raise CanonicalizationError(
            "scheme_not_allowed", f"scheme {scheme or '(none)'!r} is not allowed; use http or https"
        )
    netloc = parts.netloc
    if not netloc:
        raise CanonicalizationError("unparseable", "URL has no host")
    if "@" in netloc:
        raise CanonicalizationError(
            "userinfo_in_url", "URLs with user-info (credentials) are rejected"
        )
    host_part, port_part = netloc, None
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise CanonicalizationError("unparseable", "unterminated IPv6 literal")
        host_part, rest = netloc[: end + 1], netloc[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise CanonicalizationError(
                    "unparseable", "unexpected characters after IPv6 literal"
                )
            port_part = rest[1:]
    elif ":" in netloc:
        host_part, _, port_part = netloc.rpartition(":")
        if ":" in host_part:
            raise CanonicalizationError("unparseable", "multiple ports or unbracketed IPv6 address")
    host, ip = normalize_host(host_part)
    port = normalize_port(port_part, scheme)
    path = normalize_path(parts.path or "/")
    return CanonicalTarget(scheme=scheme, host=host, ip=ip, port=port, path=path)


def path_matches_prefix(path: str, prefix: str) -> bool:
    """Segment-boundary prefix match: '/api' matches '/api' and '/api/x', not '/apiary'."""
    if prefix in ("", "/"):
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix) or path == prefix[:-1]
    return path == prefix or path.startswith(prefix + "/")


def host_matches_wildcard(host: str, wildcard: str) -> bool:
    """'*.example.com' matches 'a.example.com' and 'a.b.example.com', never 'example.com'
    or 'badexample.com' or 'example.com.attacker.test' (label-boundary suffix match)."""
    base = wildcard[2:] if wildcard.startswith("*.") else wildcard
    return host.endswith("." + base) and len(host) > len(base) + 1
