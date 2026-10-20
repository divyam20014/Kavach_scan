"""Structured JSON logging with mandatory redaction and correlation IDs."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.correlation import get_correlation_id
from app.core.redaction import redact, redact_text

_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
            "correlation_id": get_correlation_id(),
        }
        extra = {k: v for k, v in vars(record).items() if k not in _RESERVED}
        if extra:
            entry["extra"] = redact(extra)
        if record.exc_info and record.exc_info[0] is not None:
            # Exception type only; tracebacks may carry secrets from locals/messages.
            entry["exc_type"] = record.exc_info[0].__name__
            entry["exc"] = redact_text(str(record.exc_info[1]), max_chars=500)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(RedactingJsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Uvicorn's access log prints raw query strings (possible secrets); we log requests
    # ourselves through the redactor instead.
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True
