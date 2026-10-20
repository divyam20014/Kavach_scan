"""Reject requests whose peer is not a loopback address.

Defense in depth for the localhost-only policy: `python -m app` refuses a
non-loopback bind, but the ASGI app can also be launched directly
(e.g. `uvicorn app.main:app --host 0.0.0.0`). This guard keeps such a launch
from serving remote clients until a secure remote mode exists (TBD-003).
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import is_loopback_ip

_BODY = json.dumps(
    {"detail": "This service only accepts connections from the local machine."}
).encode()


class LoopbackOnlyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        if client is not None and is_loopback_ip(client[0]):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_BODY)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _BODY})
