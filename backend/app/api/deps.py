"""FastAPI dependencies. Routers obtain storage only through `get_repository`."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from app.core.errors import ServiceUnavailableError
from app.storage.repository import StorageRepository


def get_repository(request: Request) -> StorageRepository:
    repo = getattr(request.app.state, "repository", None)
    if repo is None:
        raise ServiceUnavailableError("Storage is not initialized")
    return repo  # type: ignore[no-any-return]


Repository = Annotated[StorageRepository, Depends(get_repository)]
