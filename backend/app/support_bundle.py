"""Diagnostic support bundle export (Phase 13, MASTER_SPEC §10).

A support bundle is for **diagnosing a problem**, never for restoring state — that is what
`app/backup/archive.py` is for (Phase 10). It therefore excludes evidence blobs and full
finding records by default, redacts every value a second time defensively (on top of the
redaction every canonical record and audit event already receives at write time), and never
includes a secret: `AppSettings` cannot hold one by construction (TBD-058/TBD-068), and the
only credential-shaped setting (`online_lookup_credential_alias`) is itself only ever a
reference, never a raw value.
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from app import __version__
from app.core.redaction import redact
from app.core.settings import RuntimeSettings
from app.services.integrations import list_integration_statuses
from app.services.projects import ProjectService
from app.storage.diagnostics import diagnose
from app.storage.migrations import STORAGE_VERSION
from app.storage.repository import StorageRepository

MAX_AUDIT_EVENTS = 500
MAX_FINDINGS_PER_PROJECT = 500  # only read at all when include_findings=True


def _put_json(zf: zipfile.ZipFile, name: str, data: Any) -> None:
    # `redact()` is defense in depth: every value here already passed through redaction once
    # at write time (canonical records, audit events) or never held a secret in the first
    # place (settings, diagnostics) — this guards against a future write path that doesn't.
    zf.writestr(name, json.dumps(redact(data), indent=2, default=str, sort_keys=True))


def build_support_bundle(
    repo: StorageRepository, settings: RuntimeSettings, *, include_findings: bool = False
) -> bytes:
    """Build a diagnostic ZIP: version/storage info, settings, recent (already-redacted)
    audit events, kill-switch state, integration status, and per-project record counts.
    Evidence blobs are never included. Full finding records (still redacted a second time
    here) are included only when `include_findings=True` is explicitly passed — the default
    bundle carries counts only."""
    buf = io.BytesIO()
    generated_at = datetime.now(UTC)
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _put_json(
            zf,
            "version.json",
            {
                "app_version": __version__,
                "storage_version": STORAGE_VERSION,
                "generated_at": generated_at.isoformat(),
                "include_findings": include_findings,
                "evidence_included": False,  # a support bundle never carries evidence blobs
            },
        )

        diag = diagnose(repo.root, settings, lock_held_here=repo.instance_lock.held)
        _put_json(zf, "storage_diagnostics.json", diag.model_dump(mode="json"))

        app_settings = repo.get_settings()
        _put_json(zf, "settings.json", app_settings.model_dump(mode="json"))

        kill_switch = repo.get_kill_switch()
        _put_json(zf, "kill_switch.json", kill_switch.model_dump(mode="json"))

        audit_page = repo.audit.list(limit=MAX_AUDIT_EVENTS)
        _put_json(
            zf,
            "audit_recent.json",
            [e.model_dump(mode="json") for e in audit_page.items],
        )

        statuses = list_integration_statuses(repo)
        _put_json(zf, "integrations.json", [asdict(s) for s in statuses])

        cve_catalog = repo.get_cve_catalog()
        _put_json(
            zf,
            "cve_catalog.json",
            None
            if cve_catalog is None
            else {
                "source": cve_catalog.source,
                "catalog_version": cve_catalog.catalog_version,
                "imported_at": cve_catalog.imported_at.isoformat(),
                "entry_count": len(cve_catalog.entries),
                "stale_after_days": cve_catalog.stale_after_days,
            },  # metadata only — never the catalog's own entries
        )

        service = ProjectService(repo)
        project_entries, _errors = repo.project_summaries()
        projects_out: list[dict[str, Any]] = []
        for pid in sorted(project_entries):
            project = repo.get_project(pid)
            row: dict[str, Any] = {
                "project_id": pid,
                "name": project.name,
                "status": project.status.value,
                "counts": service.counts(pid),
            }
            projects_out.append(row)
            if include_findings:
                page = repo.list_findings(pid, limit=MAX_FINDINGS_PER_PROJECT)
                _put_json(
                    zf,
                    f"findings/{pid}.json",
                    {
                        "total": page.total,
                        "included": len(page.items),
                        "truncated": page.total > len(page.items),
                        "findings": [f.model_dump(mode="json") for f in page.items],
                    },
                )
        _put_json(zf, "projects.json", projects_out)

    return buf.getvalue()
