"""Local-only access guard.

1. Peer check: reject any TCP peer that is not a loopback IP. Defense in depth for
   the localhost-only policy: `python -m app` refuses a non-loopback bind, but the
   ASGI app can also be launched directly (`uvicorn app.main:app --host 0.0.0.0`).
2. Host check: reject requests whose Host header is not a loopback name/IP. This
   blocks DNS-rebinding attacks where a malicious web page resolves its own domain
   to 127.0.0.1 and drives the local API from the operator's browser.
Both stay until a secure remote mode exists (TBD-003).
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import is_loopback_ip


def _host_is_local(raw: str) -> bool:
    host = raw.strip().lower()
    if host.startswith("["):  # [::1]:8765
        end = host.find("]")
        if end == -1:
            return False
        name, rest = host[1:end], host[end + 1 :]
        if rest and not (rest.startswith(":") and rest[1:].isdigit()):
            return False
    else:
        name, _, port = host.partition(":")
        if port and not port.isdigit():
            return False
    return name == "localhost" or is_loopback_ip(name)


def _body(code: str, message: str) -> bytes:
    return json.dumps(
        {"error": {"code": code, "message": message, "correlation_id": None, "details": []}}
    ).encode()


class LoopbackOnlyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        if client is None or not is_loopback_ip(client[0]):
            await self._reject(
                scope,
                send,
                "non_local_client",
                "This service only accepts connections from the local machine.",
            )
            return
        hosts = [v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"host"]
        if len(hosts) != 1 or not _host_is_local(hosts[0]):
            await self._reject(
                scope,
                send,
                "invalid_host",
                "Requests must address the service as localhost, 127.0.0.1 or [::1].",
            )
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, send: Send, code: str, message: str) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = _body(code, message)
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
