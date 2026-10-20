"""Central secret redactor applied before anything reaches logs, events or evidence.

Redaction is key-based (sensitive field names) and pattern-based (token shapes in
free text). It is deliberately conservative: false positives cost readability,
false negatives leak secrets.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"
MAX_STRING_CHARS = 4000
MAX_DEPTH = 12
MAX_ITEMS = 500

# Field names whose values are always secret, regardless of content.
_SENSITIVE_KEY = re.compile(
    r"""(?ix)
    ^(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie)$
    | pass(word|wd)? | ^pwd$
    | secret | token | api[-_]?key | apikey | access[-_]?key | private[-_]?key
    | credential | ^session([-_]?id)?$ | ^sid$ | bearer | x[-_]amz[-_]security
    """
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private key blocks
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
            re.DOTALL,
        ),
        "-----BEGIN PRIVATE KEY-----" + REDACTED,
    ),
    # Credential-bearing headers anywhere in a line (raw HTTP text or log prose):
    # everything after the header name up to the end of the line is dropped.
    (
        re.compile(
            r"(?i)(?<![\w\"'-])((?:proxy-)?authorization|set-cookie|cookie|x-api-key|x-auth-token)"
            r"[ \t]*:(?![ \t]*[\"']?\[REDACTED)[^\r\n]*"
        ),
        r"\1: " + REDACTED,
    ),
    # Quoted keys as in JSON or Python reprs: "password": "x", 'Cookie': 'a=b'
    (
        re.compile(
            r"(?i)([\"'])([\w-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|access[_-]?key|"
            r"private[_-]?key|credential|cookie|authorization|session(?:[_-]?id)?)[\w-]*)\1"
            r"(\s*[:=]\s*)(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s,;}\]]+)"
        ),
        r"\1\2\1\3" + '"' + REDACTED + '"',
    ),
    # Authorization schemes
    (re.compile(r"(?i)\b(bearer|basic|digest|token)\s+[A-Za-z0-9\-._~+/=]{8,}"), r"\1 " + REDACTED),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), REDACTED),
    # AWS access key IDs
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # Common vendor token prefixes (GitHub, Slack, Stripe, Google API)
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,})"), REDACTED),
    (re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), REDACTED),
    # URL user-info: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]*@"), r"\1" + REDACTED + "@"),
    # Secret-looking query/form parameters
    (
        re.compile(
            r"(?i)([?&;](?:access_token|refresh_token|id_token|token|api[_-]?key|apikey|key|"
            r"password|passwd|pwd|secret|client_secret|session|sessionid|sid|sig|signature|"
            r"auth|code)=)[^&#\s]+"
        ),
        r"\1" + REDACTED,
    ),
    # key=value / key: value assignments in free text
    (
        re.compile(
            r"(?i)(?<![\w\"'])((?:[\w-]*(?:password|passwd|secret|token|api[_-]?key|apikey|"
            r"access[_-]?key|private[_-]?key|credential)[\w-]*|pwd)\s*[=:]\s*)"
            r"(?!\"?\[REDACTED)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1" + REDACTED,
    ),
]


def is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY.search(key))


def redact_text(text: str, max_chars: int = MAX_STRING_CHARS) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > max_chars:
        text = text[:max_chars] + "...[TRUNCATED]"
    return text


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Return a redacted deep copy of JSON-like data (dict/list/str/scalars)."""
    if _depth > MAX_DEPTH:
        return "[TRUNCATED-DEPTH]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_ITEMS:
                out["__truncated__"] = True
                break
            key = str(k)
            out[key] = REDACTED if is_sensitive_key(key) else redact(v, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple | set | frozenset):
        items = list(value)
        result = [redact(v, _depth=_depth + 1) for v in items[:MAX_ITEMS]]
        if len(items) > MAX_ITEMS:
            result.append("[TRUNCATED-ITEMS]")
        return result
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))


def redact_headers(headers: Mapping[str, str] | list[tuple[str, str]]) -> dict[str, str]:
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    return {k: (REDACTED if is_sensitive_key(k) else redact_text(v)) for k, v in pairs}
