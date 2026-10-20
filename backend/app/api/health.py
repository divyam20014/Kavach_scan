"""Health and version endpoints. No filesystem or network access."""

from __future__ import annotations

import platform

from fastapi import APIRouter
from pydantic import BaseModel

from app import __version__
from app.core.config import PRODUCT_NAME

router = APIRouter(prefix="/api", tags=["system"])


class HealthResponse(BaseModel):
    status: str


class VersionResponse(BaseModel):
    name: str
    version: str
    python: str
    scanning_available: bool


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/version", response_model=VersionResponse)
def version() -> VersionResponse:
    # scanning_available is a fact, not a toggle: no scanner exists in Phase 00.
    return VersionResponse(
        name=PRODUCT_NAME,
        version=__version__,
        python=platform.python_version(),
        scanning_available=False,
    )
