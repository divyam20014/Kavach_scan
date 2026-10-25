"""Append-only audit log. Metadata is redacted here, before persistence, always."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.correlation import get_correlation_id
from app.core.redaction import redact, redact_text
from app.models.audit import AuditAction, AuditEvent
from app.models.common import StrictModel, new_id
from app.storage.jsonl import JsonlLog


class AuditPage(StrictModel):
    items: list[AuditEvent]
    offset: int
    limit: int
    has_more: bool
    corrupt_lines: int


class AuditLog:
    def __init__(
        self,
        directory: Path,
        *,
        rotate_bytes: int,
        lock_timeout: float,
        lock_root: Path | None = None,
    ) -> None:
        self._log = JsonlLog(
            directory,
            "audit",
            rotate_bytes=rotate_bytes,
            lock_timeout=lock_timeout,
            lock_root=lock_root,
        )

    @property
    def log(self) -> JsonlLog:
        return self._log

    def record(
        self,
        action: AuditAction,
        *,
        project_id: str | None = None,
        target_ids: list[str] | None = None,
        outcome: str = "success",
        metadata: dict[str, Any] | None = None,
        actor: str = "local-operator",
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=new_id("event"),
            action=action,
            project_id=project_id,
            target_ids=[redact_text(t, max_chars=500) for t in (target_ids or [])],
            outcome=outcome,  # type: ignore[arg-type]
            metadata=redact(metadata or {}),
            actor=actor,
            correlation_id=get_correlation_id(),
        )
        self.append(event)
        return event

    def append(self, event: AuditEvent) -> None:
        data = event.model_dump(mode="json")
        data["metadata"] = redact(data["metadata"])  # even pre-built events are redacted
        self._log.append(data)

    def list(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        project_id: str | None = None,
        action: AuditAction | None = None,
        target_id: str | None = None,
    ) -> AuditPage:
        def parse(obj: dict[str, Any]) -> AuditEvent:
            try:
                return AuditEvent.model_validate(obj)
            except ValidationError as exc:
                raise ValueError("invalid audit line") from exc

        def keep(event: AuditEvent) -> bool:
            return (
                (project_id is None or event.project_id == project_id)
                and (action is None or event.action == action)
                and (target_id is None or target_id in event.target_ids)
            )

        items, corrupt, more = self._log.read_newest(
            offset=offset, limit=limit, parse=parse, predicate=keep
        )
        return AuditPage(
            items=items, offset=offset, limit=limit, has_more=more, corrupt_lines=corrupt
        )
