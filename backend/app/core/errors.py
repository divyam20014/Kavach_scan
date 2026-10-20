"""Typed application errors and the single JSON error envelope.

Every error response has the shape:
    {"error": {"code": str, "message": str, "correlation_id": str | None, "details": [...]}}
Messages are safe to show to the operator: no stack traces, no input echoes.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.correlation import get_correlation_id

log = logging.getLogger("app.errors")


class ErrorDetail(BaseModel):
    loc: list[str | int] = Field(default_factory=list)
    message: str
    type: str | None = None


class ErrorBody(BaseModel):
    code: str
    message: str
    correlation_id: str | None = None
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: ErrorBody


class AppError(Exception):
    """Base for errors that map to a specific HTTP status and stable code."""

    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, *, details: list[ErrorDetail] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or []


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class ValidationFailedError(AppError):
    status_code = 422
    code = "validation_failed"


class ServiceUnavailableError(AppError):
    status_code = 503
    code = "service_unavailable"


_STATUS_CODES = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_failed",
    503: "service_unavailable",
}


def error_payload(
    code: str, message: str, details: list[ErrorDetail] | None = None
) -> dict[str, Any]:
    body = ErrorBody(
        code=code, message=message, correlation_id=get_correlation_id(), details=details or []
    )
    return ErrorResponse(error=body).model_dump(mode="json")


def _json(
    status: int, code: str, message: str, details: list[ErrorDetail] | None = None
) -> JSONResponse:
    return JSONResponse(status_code=status, content=error_payload(code, message, details))


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return _json(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo `input`/`ctx`: they may contain secrets the client sent.
        details = [
            ErrorDetail(
                loc=list(e.get("loc", ())), message=str(e.get("msg", "")), type=e.get("type")
            )
            for e in exc.errors()[:50]
        ]
        return _json(422, "validation_failed", "Request validation failed.", details)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else code.replace("_", " ")
        return _json(exc.status_code, code, message)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error: %s", type(exc).__name__, exc_info=exc)
        return _json(500, "internal_error", "An internal error occurred. See the server log.")
