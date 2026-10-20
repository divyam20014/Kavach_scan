"""Integrity checker: reports problems without deleting canonical data.

`repair=True` only performs safe, derivable actions: rebuilding indexes and removing
temp files (the caller must hold the instance lock). Corrupt or invalid records are
reported for operator action, never auto-deleted (docs/STORAGE_FORMATS.md §9–10).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from app.models.common import ShortText, StrictModel, UtcDatetime, is_valid_id, utc_now
from app.storage.atomic import TMP_RE, cleanup_temp_files
from app.storage.errors import StorageError
from app.storage.paths import is_link_like
from app.storage.repository import ASSETS, CHILD_COLLECTIONS, EVIDENCE, FINDINGS, StorageRepository

MAX_ISSUES = 1000

IssueKind = Literal[
    "corrupt_record",
    "invalid_record",
    "unsupported_version",
    "missing_project_file",
    "unexpected_entry",
    "link_in_data_dir",
    "dangling_evidence_ref",
    "missing_blob",
    "orphan_blob",
    "temp_file",
    "project_pending_delete",
]

_CODE_TO_KIND: dict[str, IssueKind] = {
    "record_corrupt": "corrupt_record",
    "record_too_large": "corrupt_record",
    "record_invalid": "invalid_record",
    "schema_version_unsupported": "unsupported_version",
}


class IntegrityIssue(StrictModel):
    kind: IssueKind
    project_id: str | None = None
    record_id: str | None = None
    location: ShortText = ""  # relative to the data root; never absolute
    message: ShortText = ""


class IntegrityReport(StrictModel):
    checked_at: UtcDatetime = Field(default_factory=utc_now)
    repair: bool
    projects_checked: int = 0
    records_checked: int = 0
    issues: list[IntegrityIssue] = Field(default_factory=list)
    issues_truncated: bool = False
    indexes_rebuilt: int = 0
    temp_files_removed: int = 0

    @property
    def ok(self) -> bool:
        return not self.issues


class _Collector:
    def __init__(self, report: IntegrityReport) -> None:
        self.report = report

    def add(self, issue: IntegrityIssue) -> None:
        if len(self.report.issues) >= MAX_ISSUES:
            self.report.issues_truncated = True
            return
        self.report.issues.append(issue)


def check_integrity(repo: StorageRepository, *, repair: bool) -> IntegrityReport:
    report = IntegrityReport(repair=repair)
    out = _Collector(report)
    rel = repo.paths.relative

    for dirpath, dirnames, filenames in os.walk(repo.root, followlinks=False):
        base = Path(dirpath)
        for name in list(dirnames):
            if is_link_like(base / name):
                out.add(
                    IntegrityIssue(
                        kind="link_in_data_dir",
                        location=rel(base / name),
                        message="Symlink/junction inside the data directory is ignored",
                    )
                )
                dirnames.remove(name)
        for name in filenames:
            if is_link_like(base / name):
                out.add(
                    IntegrityIssue(
                        kind="link_in_data_dir",
                        location=rel(base / name),
                        message="Symlink inside the data directory is ignored",
                    )
                )
            elif TMP_RE.fullmatch(name) and not repair:
                out.add(
                    IntegrityIssue(
                        kind="temp_file",
                        location=rel(base / name),
                        message="Leftover temp file from an interrupted write",
                    )
                )
    if repair:
        report.temp_files_removed = cleanup_temp_files(repo.root)

    projects_dir = repo.paths.path("projects")
    for entry in sorted(os.scandir(projects_dir), key=lambda e: e.name):
        if entry.name.startswith(".") or entry.is_symlink() or entry.is_junction():
            continue
        if not (entry.is_dir(follow_symlinks=False) and is_valid_id("project", entry.name)):
            out.add(
                IntegrityIssue(
                    kind="unexpected_entry",
                    location=rel(Path(entry.path)),
                    message="Unrecognized entry in projects/",
                )
            )
            continue
        _check_project(repo, entry.name, out)

    if repair:
        report.indexes_rebuilt = repo.rebuild_all_indexes()
    return report


def _check_project(repo: StorageRepository, pid: str, out: _Collector) -> None:
    report = out.report
    rel = repo.paths.relative
    pdir = repo.paths.path("projects", pid)
    if (pdir / ".deleting").exists():
        out.add(
            IntegrityIssue(
                kind="project_pending_delete",
                project_id=pid,
                location=rel(pdir),
                message="Project deletion was interrupted; delete it again to finish",
            )
        )
        return
    report.projects_checked += 1
    if not (pdir / "project.json").is_file():
        out.add(
            IntegrityIssue(
                kind="missing_project_file",
                project_id=pid,
                location=rel(pdir),
                message="project.json is missing",
            )
        )
        return
    try:
        repo.get_project(pid)
        report.records_checked += 1
    except StorageError as exc:
        out.add(
            IntegrityIssue(
                kind=_CODE_TO_KIND.get(exc.code, "corrupt_record"),
                project_id=pid,
                record_id=pid,
                location=rel(pdir / "project.json"),
                message=exc.message,
            )
        )

    evidence_ids: set[str] = set()
    referenced: list[tuple[str, str]] = []
    for spec in CHILD_COLLECTIONS:
        cdir = pdir / spec.dirname
        if not cdir.is_dir():
            continue
        flat = spec.nested_file is None
        for entry in os.scandir(cdir):
            if entry.name.startswith(".") or entry.is_symlink() or entry.is_junction():
                continue
            stem = entry.name[:-5] if flat and entry.name.endswith(".json") else entry.name
            if spec is EVIDENCE and entry.name.endswith(".bin"):
                if not (cdir / f"{entry.name[:-4]}.json").exists():
                    out.add(
                        IntegrityIssue(
                            kind="orphan_blob",
                            project_id=pid,
                            location=rel(Path(entry.path)),
                            message="Evidence blob without metadata",
                        )
                    )
                continue
            if not is_valid_id(spec.kind, stem) or (flat and not entry.name.endswith(".json")):
                out.add(
                    IntegrityIssue(
                        kind="unexpected_entry",
                        project_id=pid,
                        location=rel(Path(entry.path)),
                        message=f"Unrecognized entry in {spec.dirname}/",
                    )
                )
                continue
            try:
                record = repo._get_child(spec, pid, stem)  # noqa: SLF001 - same package
                report.records_checked += 1
            except StorageError as exc:
                out.add(
                    IntegrityIssue(
                        kind=_CODE_TO_KIND.get(exc.code, "corrupt_record"),
                        project_id=pid,
                        record_id=stem,
                        location=rel(Path(entry.path)),
                        message=exc.message,
                    )
                )
                continue
            if spec is EVIDENCE:
                evidence_ids.add(stem)
                if record.has_blob and not (cdir / f"{stem}.bin").is_file():
                    out.add(
                        IntegrityIssue(
                            kind="missing_blob",
                            project_id=pid,
                            record_id=stem,
                            location=rel(Path(entry.path)),
                            message="Evidence blob file is missing",
                        )
                    )
            elif spec in (FINDINGS, ASSETS):
                referenced.extend((stem, eid) for eid in record.evidence_ids)
    for record_id, evidence_id in referenced:
        if evidence_id not in evidence_ids:
            out.add(
                IntegrityIssue(
                    kind="dangling_evidence_ref",
                    project_id=pid,
                    record_id=record_id,
                    message=f"References missing evidence {evidence_id}",
                )
            )
