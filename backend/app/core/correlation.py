"""Request correlation IDs carried through logs, audit events and (later) jobs."""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEADER = "x-request-id"
_VALID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_current: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def get_correlation_id() -> str | None:
    return _current.get()


def set_correlation_id(value: str | None) -> None:
    _current.set(value)


def accept_or_generate(candidate: str | None) -> str:
    """Accept a client-supplied ID only if it is short and charset-safe."""
    if candidate and _VALID.fullmatch(candidate):
        return candidate
    return new_correlation_id()


class CorrelationIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = None
        for name, value in scope.get("headers", []):
            if name == HEADER.encode():
                supplied = value.decode("latin-1")
                break
        cid = accept_or_generate(supplied)
        token = _current.set(cid)
        scope.setdefault("state", {})["correlation_id"] = cid

        async def send_with_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k != HEADER.encode()]
                headers.append((HEADER.encode(), cid.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            _current.reset(token)
