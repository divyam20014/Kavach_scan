"""Sanitized evidence excerpts. Bodies are never stored whole: at most a short window
around the matched signature, then redacted again by the storage layer."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from app.core.redaction import is_sensitive_key, redact_text
from app.integrations.http_service import HttpExchange
from app.scanners.webapp.rules import EvidenceDraft

MAX_BODY_WINDOW = 600
MAX_HEADERS_SHOWN = 40


def describe_cookie(raw: str) -> str:
    """'name=[value omitted]; Path=/; HttpOnly' — attributes kept, value never shown."""
    name, _, rest = raw.partition("=")
    attrs = rest.split(";", 1)[1].strip() if ";" in rest else ""
    return f"{name.strip()[:100]}=[value omitted]" + (f"; {attrs[:300]}" if attrs else "")


def request_excerpt(exchange: HttpExchange, url: str | None = None) -> str:
    target = url or exchange.final_url
    parts = urlsplit(target)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    lines = [f"{exchange.method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
    for name, value in list(exchange.request_headers.items())[:20]:
        lines.append(f"{name}: {value}")
    return redact_text("\n".join(lines), max_chars=2000)


def response_excerpt(exchange: HttpExchange, *, body_match: str | None = None) -> str:
    response = exchange.response
    if response is None:
        return f"(no response: {exchange.error_kind} {exchange.error})"[:500]
    lines = [f"HTTP/1.1 {response.status} {response.reason}".rstrip()]
    for name, value in response.headers[:MAX_HEADERS_SHOWN]:
        if name.lower() == "set-cookie":
            lines.append(f"Set-Cookie (sanitized): {describe_cookie(value)}")
        elif is_sensitive_key(name):
            lines.append(f"{name}: [REDACTED]")
        else:
            lines.append(f"{name}: {value[:300]}")
    if body_match:
        lines.append("")
        lines.append(body_window(response.body, body_match))
    return redact_text("\n".join(lines), max_chars=6000)


def body_window(body: bytes, needle: str, width: int = MAX_BODY_WINDOW) -> str:
    text = body.decode("utf-8", "replace")
    index = text.find(needle)
    if index < 0:
        index = text.lower().find(needle.lower())
    if index < 0:
        return "[body excerpt omitted]"
    start = max(0, index - width // 3)
    snippet = text[start : start + width]
    prefix = "…" if start else ""
    suffix = "…" if start + width < len(text) else ""
    return f"[body excerpt, {len(body)} bytes observed]\n{prefix}{snippet}{suffix}"


def http_evidence(
    exchange: HttpExchange, *, body_match: str | None = None, url: str | None = None
) -> EvidenceDraft:
    body = exchange.response.body if exchange.response is not None else b""
    return EvidenceDraft(
        evidence_type="http_exchange",
        request_excerpt=request_excerpt(exchange, url),
        response_excerpt=response_excerpt(exchange, body_match=body_match),
        bytes_observed=len(body),
        sha256=hashlib.sha256(body).hexdigest() if body else None,
        truncated=bool(exchange.response is not None and exchange.response.truncated),
    )
