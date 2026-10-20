"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from app import __version__
from app.api import health
from app.core.config import PRODUCT_NAME
from app.core.loopback_guard import LoopbackOnlyMiddleware


def create_app() -> FastAPI:
    app = FastAPI(title=PRODUCT_NAME, version=__version__)
    app.include_router(health.router)
    app.add_middleware(LoopbackOnlyMiddleware)
    return app


app = create_app()
