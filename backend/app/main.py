"""FastAPI application factory.

The data directory is opened in the lifespan (or passed in by `python -m app`, which
opens it before starting uvicorn so startup errors are reported cleanly). Opening
acquires the single-instance lock for the data root.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api import health, projects, scope
from app.core.config import PRODUCT_NAME
from app.core.correlation import CorrelationIdMiddleware
from app.core.errors import ErrorResponse, install_error_handlers
from app.core.loopback_guard import LoopbackOnlyMiddleware
from app.core.request_guards import RequestLogMiddleware, RequestSizeLimitMiddleware
from app.core.settings import RuntimeSettings, load_settings
from app.storage.integrity import check_integrity
from app.storage.repository import StorageRepository
from app.web import SecurityHeadersMiddleware, mount_ui

log = logging.getLogger("app.main")


def create_app(
    settings: RuntimeSettings | None = None,
    repository: StorageRepository | None = None,
    *,
    serve_ui: bool = False,
) -> FastAPI:
    """Build the app. `serve_ui=True` also serves the built frontend (frontend/dist)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = repository is None
        repo = repository
        if repo is None:
            repo = StorageRepository.open(settings or load_settings())
        try:
            app.state.repository = repo
            app.state.last_integrity = check_integrity(repo, repair=True)
            if not app.state.last_integrity.ok:
                log.warning(
                    "integrity check reported %d issue(s)", len(app.state.last_integrity.issues)
                )
            yield
        finally:
            app.state.repository = None
            if owned:
                repo.close()

    effective = settings or load_settings()
    app = FastAPI(
        title=PRODUCT_NAME,
        version=__version__,
        lifespan=lifespan,
        responses={"default": {"model": ErrorResponse}},
    )
    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(projects.router)
    app.include_router(scope.router)
    if serve_ui and not mount_ui(app):
        log.info("frontend build not found; serving the API only")
    # add_middleware prepends: the last added runs first (outermost).
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLogMiddleware)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=effective.max_request_bytes)
    app.add_middleware(LoopbackOnlyMiddleware)
    return app


app = create_app(serve_ui=True)
