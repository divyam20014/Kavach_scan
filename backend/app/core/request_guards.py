"""Request-size limit and redacted request logging middleware."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import error_payload
from app.core.redaction import redact_text

log = logging.getLogger("app.request")

# Multipart framing (boundaries, per-part headers) adds a small amount of overhead on top of
# the raw file content; the override limits below already carry their own margin, but this
# keeps a maximum-sized upload from being rejected by a handful of extra multipart bytes.
_MULTIPART_OVERHEAD_BYTES = 64 * 1024

PathLimit = tuple[Callable[[str, str], bool], int]


class RequestSizeLimitMiddleware:
    """Reject bodies above a byte limit with 413, whether Content-Length is declared or not.

    `max_bytes` is the default applied to every route — sized for an ordinary JSON request
    body, not a file upload. A handful of routes legitimately accept much larger bodies (a
    CVE catalog, an import file, a project backup archive) and each already declares and
    enforces its own, often much larger, size cap deeper in its own code (TBD-009 et al.);
    `path_limits` lets those specific routes use their own documented limit here too, so this
    outer guard is never the thing silently making a within-spec upload impossible (found in
    Phase 12 verification: every upload route's documented limit was unreachable above the
    1 MiB JSON-sized default, and the backup archive's 200 MiB limit was unreachable even at
    this setting's configurable maximum).
    """

    def __init__(self, app: ASGIApp, max_bytes: int, path_limits: Sequence[PathLimit] = ()) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.path_limits = path_limits

    def _limit_for(self, method: str, path: str) -> int:
        limit = self.max_bytes
        for predicate, override in self.path_limits:
            if predicate(method, path):
                limit = max(limit, override + _MULTIPART_OVERHEAD_BYTES)
        return limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit_for(scope.get("method", ""), scope.get("path", ""))
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._reject(send, 400, "bad_request", "Invalid Content-Length header.")
                    return
                if declared > limit:
                    await self._reject(send, 413, "payload_too_large", "Request body is too large.")
                    return
        # Buffer (bounded) so undeclared/chunked bodies are limited too.
        chunks: list[bytes] = []
        total = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > limit:
                await self._reject(send, 413, "payload_too_large", "Request body is too large.")
                return
            chunks.append(body)
            more = message.get("more_body", False)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Send, status: int, code: str, message: str) -> None:
        import json

        body = json.dumps(error_payload(code, message)).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class RequestLogMiddleware:
    """One structured log line per request. Query strings are redacted, bodies never logged."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            query = scope.get("query_string", b"").decode("latin-1")
            target = scope.get("path", "") + (f"?{query}" if query else "")
            log.info(
                "%s %s -> %s (%.1f ms)",
                scope.get("method", "?"),
                redact_text(target, max_chars=500),
                status,
                (time.perf_counter() - start) * 1000,
            )
