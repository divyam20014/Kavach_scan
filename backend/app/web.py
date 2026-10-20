"""Serve the built single-page UI (frontend/dist) from the API process, if present.

Only files directly inside the build directory (and its `assets/` folder, via
StaticFiles) are served; every other non-API path returns index.html so client-side
routes survive a page reload. Request paths are never joined onto the filesystem.
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.settings import repo_root

_TOP_LEVEL_FILE = re.compile(r"^[A-Za-z0-9_-]{1,64}\.(svg|ico|png|txt|webmanifest)$")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)


def default_ui_dir() -> Path:
    return repo_root() / "frontend" / "dist"


def mount_ui(app: FastAPI, ui_dir: Path | None = None) -> bool:
    dist = (ui_dir or default_ui_dir()).resolve()
    index = dist / "index.html"
    if not index.is_file():
        return False
    top_level = {
        p.name: p for p in dist.iterdir() if p.is_file() and _TOP_LEVEL_FILE.fullmatch(p.name)
    }
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="ui-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        if full_path in top_level:
            return FileResponse(top_level[full_path])
        return FileResponse(index, headers={"Cache-Control": "no-store"})

    return True


class SecurityHeadersMiddleware:
    """Baseline browser hardening for every response (fuller review in Phase 12)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                names = {k.lower() for k, _ in headers}
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"referrer-policy": b"no-referrer",
                    b"x-frame-options": b"DENY",
                    b"cross-origin-opener-policy": b"same-origin",
                }
                path = scope.get("path", "")
                if not path.startswith(("/docs", "/redoc")):  # Swagger UI loads its own CDN assets
                    extra[b"content-security-policy"] = CSP.encode()
                headers.extend((k, v) for k, v in extra.items() if k not in names)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, with_headers)
