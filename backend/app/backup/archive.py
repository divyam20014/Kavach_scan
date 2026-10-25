"""Project backup export/preview/restore (MASTER_SPEC §10.2 items 6-7, Phase 10).

Export writes every canonical record under a project (never the derived `index/`, which is
disposable and rebuilt automatically) into a single ZIP with a manifest carrying checksums,
schema versions and record counts. Restore always re-validates every record through its own
Pydantic model before writing anything — a byte-identical-looking JSON file is never trusted
just because it parses as JSON. Evidence **blobs** (not metadata) are the one thing the
operator can choose to exclude, since they are the largest and most sensitive payload.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from app import __version__
from app.backup.safety import ArchiveSafetyError, SafeMember, safe_extract_all
from app.core.errors import ConflictError, ValidationFailedError
from app.models.asset import Asset
from app.models.common import Page
from app.models.evidence import EvidenceMetadata
from app.models.finding import Finding
from app.models.import_artifact import ImportArtifact
from app.models.project import Project
from app.models.scan import ScanJob
from app.storage.errors import StorageError
from app.storage.migrations import STORAGE_VERSION
from app.storage.repository import StorageRepository

MANIFEST_SCHEMA_VERSION = 1

T = TypeVar("T")
_M = TypeVar("_M", bound=BaseModel)


def _validate_record(model: type[_M], data: dict[str, Any], label: str) -> _M:
    """`model_validate` on fully attacker-controlled archive bytes: a shape mismatch must
    become a clean, safe 422 (never a raw pydantic error echoing the attacker's input, and
    never an unhandled-exception 500)."""
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ValidationFailedError(
            f"{label} does not match the expected schema ({exc.error_count()} error(s))"
        ) from exc


def _iter_all(lister: Callable[..., Page[T]], limit: int = 200, pages: int = 200) -> list[T]:
    out: list[T] = []
    offset = 0
    for _ in range(pages):
        page = lister(offset=offset, limit=limit)
        out.extend(page.items)
        offset += limit
        if offset >= page.total:
            break
    return out


@dataclass
class ArchiveManifest:
    schema_version: int
    exported_at: str
    app_version: str
    storage_version: int
    project_id: str
    include_evidence_blobs: bool
    counts: dict[str, int]
    checksums: dict[str, str]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "exported_at": self.exported_at,
            "app_version": self.app_version,
            "storage_version": self.storage_version,
            "project_id": self.project_id,
            "include_evidence_blobs": self.include_evidence_blobs,
            "counts": self.counts,
            "checksums": self.checksums,
        }


def export_archive(
    repo: StorageRepository, project_id: str, *, include_evidence_blobs: bool = True
) -> bytes:
    project = repo.get_project(project_id)
    scans = _iter_all(lambda **kw: repo.list_scans(project_id, **kw))
    findings = _iter_all(lambda **kw: repo.list_findings(project_id, **kw))
    assets = _iter_all(lambda **kw: repo.list_assets(project_id, **kw))
    evidence = _iter_all(lambda **kw: repo.list_evidence(project_id, **kw))
    imports = _iter_all(lambda **kw: repo.list_imports(project_id, **kw))

    buf = io.BytesIO()
    checksums: dict[str, str] = {}
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:

        def put(name: str, data: bytes) -> None:
            import hashlib

            zf.writestr(name, data)
            checksums[name] = hashlib.sha256(data).hexdigest()

        put("project.json", project.model_dump_json(indent=2).encode("utf-8"))
        for s in scans:
            put(f"scans/{s.scan_id}.json", s.model_dump_json(indent=2).encode("utf-8"))
        for f in findings:
            put(f"findings/{f.finding_id}.json", f.model_dump_json(indent=2).encode("utf-8"))
        for a in assets:
            put(f"assets/{a.asset_id}.json", a.model_dump_json(indent=2).encode("utf-8"))
        for e in evidence:
            put(f"evidence/{e.evidence_id}.json", e.model_dump_json(indent=2).encode("utf-8"))
            if include_evidence_blobs and e.has_blob:
                try:
                    blob = repo.read_evidence_blob(project_id, e.evidence_id)
                except StorageError:
                    continue
                put(f"evidence/{e.evidence_id}.bin", blob)
        for imp in imports:
            put(
                f"imports/{imp.import_id}/import.json",
                imp.model_dump_json(indent=2).encode("utf-8"),
            )
            try:
                raw = repo.read_import_raw(project_id, imp.import_id)
            except StorageError:
                continue
            put(f"imports/{imp.import_id}/raw.bin", raw)

        manifest = ArchiveManifest(
            schema_version=MANIFEST_SCHEMA_VERSION,
            exported_at=datetime.now(project.created_at.tzinfo).isoformat(),
            app_version=__version__,
            storage_version=STORAGE_VERSION,
            project_id=project_id,
            include_evidence_blobs=include_evidence_blobs,
            counts={
                "scans": len(scans),
                "findings": len(findings),
                "assets": len(assets),
                "evidence": len(evidence),
                "imports": len(imports),
            },
            checksums=dict(checksums),
        )
        zf.writestr("manifest.json", json.dumps(manifest.as_dict(), indent=2))
    return buf.getvalue()


@dataclass
class ArchivePreview:
    project_id: str
    project_name: str
    exported_at: str
    app_version: str
    storage_version: int
    include_evidence_blobs: bool
    counts: dict[str, int]
    checksum_mismatches: list[str]
    project_already_exists: bool
    warnings: list[str] = field(default_factory=list)


def _parse_members(raw: bytes) -> tuple[dict[str, ArchiveManifest], dict[str, SafeMember]]:
    try:
        members = safe_extract_all(raw)
    except ArchiveSafetyError as exc:
        raise ValidationFailedError(f"invalid backup archive: {exc}") from exc
    by_name = {m.name: m for m in members}
    if "manifest.json" not in by_name:
        raise ValidationFailedError("backup archive is missing manifest.json")
    try:
        raw_manifest = json.loads(by_name["manifest.json"].data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationFailedError(f"manifest.json is not valid JSON: {exc}") from exc
    valid_schema = (
        isinstance(raw_manifest, dict)
        and raw_manifest.get("schema_version") == MANIFEST_SCHEMA_VERSION
    )
    if not valid_schema:
        raise ValidationFailedError("unsupported or missing manifest schema_version")
    try:
        manifest = ArchiveManifest(
            schema_version=raw_manifest["schema_version"],
            exported_at=raw_manifest["exported_at"],
            app_version=raw_manifest["app_version"],
            storage_version=raw_manifest["storage_version"],
            project_id=raw_manifest["project_id"],
            include_evidence_blobs=bool(raw_manifest["include_evidence_blobs"]),
            counts=dict(raw_manifest["counts"]),
            checksums=dict(raw_manifest["checksums"]),
        )
    except (KeyError, TypeError) as exc:
        raise ValidationFailedError(f"manifest.json is missing a required field: {exc}") from exc
    return {"manifest": manifest}, by_name


def _verify_checksums(manifest: ArchiveManifest, by_name: dict[str, SafeMember]) -> list[str]:
    import hashlib

    mismatches = []
    for name, expected in manifest.checksums.items():
        member = by_name.get(name)
        if member is None:
            mismatches.append(f"{name}: missing from archive")
            continue
        actual = hashlib.sha256(member.data).hexdigest()
        if actual != expected:
            mismatches.append(f"{name}: checksum mismatch")
    return mismatches


def _check_project_id_consistency(
    manifest: ArchiveManifest, by_name: dict[str, SafeMember]
) -> list[str]:
    """The manifest's `project_id` is attacker/exporter-controlled and is used to decide
    whether a restore would collide with an existing project. If it disagreed with what
    `project.json` itself declares, an operator's "already exists" / overwrite decision would
    be made against the wrong project. Checked before any collision decision or write."""
    problems: list[str] = []
    member = by_name.get("project.json")
    if member is None:
        return problems  # reported separately by the project.json presence check
    try:
        project_raw = json.loads(member.data)
    except (ValueError, UnicodeDecodeError):
        return problems  # reported separately
    if isinstance(project_raw, dict) and project_raw.get("project_id") != manifest.project_id:
        problems.append("manifest.json project_id does not match project.json's own project_id")
    return problems


def _check_every_record_belongs_to_this_project(
    manifest: ArchiveManifest, by_name: dict[str, SafeMember]
) -> list[str]:
    """Every scan/finding/asset/evidence record carries its own `project_id` field, and the
    storage layer writes a record to whatever project *that field* names — not necessarily the
    project being restored. Without this check, a crafted archive could smuggle records into a
    different, already-existing project in the destination data directory. Checked up front, for
    every record, before any write happens."""
    problems: list[str] = []
    for name, member in sorted(by_name.items()):
        is_json_record = name.startswith(
            ("scans/", "findings/", "assets/", "evidence/")
        ) and name.endswith(".json")
        is_import_record = name.startswith("imports/") and name.endswith("/import.json")
        is_record = is_json_record or is_import_record
        if not is_record:
            continue
        try:
            data = json.loads(member.data)
        except (ValueError, UnicodeDecodeError):
            problems.append(f"{name}: not valid JSON")
            continue
        if not isinstance(data, dict):
            problems.append(f"{name}: does not contain a JSON object")
            continue
        if data.get("project_id") != manifest.project_id:
            problems.append(f"{name}: project_id does not match this archive's project")
    return problems


def preview_archive(repo: StorageRepository, raw: bytes) -> ArchivePreview:
    """Read-only: validates the archive and reports what a restore would do. Never writes
    anything — the Phase 10 acceptance criterion "preview before restore"."""
    parsed, by_name = _parse_members(raw)
    manifest = parsed["manifest"]
    mismatches = _verify_checksums(manifest, by_name)
    mismatches.extend(_check_project_id_consistency(manifest, by_name))
    mismatches.extend(_check_every_record_belongs_to_this_project(manifest, by_name))
    try:
        project_raw = json.loads(by_name["project.json"].data)
        project_name = str(project_raw.get("name", "?"))
    except (KeyError, ValueError):
        project_name = "?"
        mismatches.append("project.json: missing or invalid")
    already_exists = False
    try:
        repo.get_project(manifest.project_id)
        already_exists = True
    except StorageError:
        pass
    warnings = []
    if manifest.app_version != __version__:
        warnings.append(
            f"archive was exported by app version {manifest.app_version}, this build is "
            f"{__version__}"
        )
    if manifest.storage_version != STORAGE_VERSION:
        warnings.append(
            f"archive storage_version {manifest.storage_version} differs from this build's "
            f"{STORAGE_VERSION}"
        )
    return ArchivePreview(
        project_id=manifest.project_id,
        project_name=project_name,
        exported_at=manifest.exported_at,
        app_version=manifest.app_version,
        storage_version=manifest.storage_version,
        include_evidence_blobs=manifest.include_evidence_blobs,
        counts=manifest.counts,
        checksum_mismatches=mismatches,
        project_already_exists=already_exists,
        warnings=warnings,
    )


@dataclass
class RestoreResult:
    project_id: str
    counts: dict[str, int]


def restore_archive(
    repo: StorageRepository, raw: bytes, *, confirmed: bool, overwrite: bool = False
) -> RestoreResult:
    if not confirmed:
        raise ValidationFailedError("explicit confirmation is required to restore a backup")
    parsed, by_name = _parse_members(raw)
    manifest = parsed["manifest"]
    mismatches = _verify_checksums(manifest, by_name)
    if mismatches:
        raise ValidationFailedError(
            "backup archive failed checksum verification: " + "; ".join(mismatches[:10])
        )
    id_problems = _check_project_id_consistency(manifest, by_name)
    id_problems.extend(_check_every_record_belongs_to_this_project(manifest, by_name))
    if id_problems:
        raise ValidationFailedError(
            "backup archive has inconsistent project ids: " + "; ".join(id_problems[:10])
        )

    already_exists = False
    try:
        repo.get_project(manifest.project_id)
        already_exists = True
    except StorageError:
        pass
    if already_exists and not overwrite:
        raise ConflictError(
            f"a project with id {manifest.project_id} already exists; pass overwrite=true "
            "to explicitly replace it, or restore is refused to preserve current data"
        )
    if already_exists and overwrite:
        repo.delete_project(manifest.project_id)

    def _get_json(name: str) -> dict[str, Any]:
        member = by_name.get(name)
        if member is None:
            raise ValidationFailedError(f"backup archive is missing {name}")
        try:
            data = json.loads(member.data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValidationFailedError(f"{name} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationFailedError(f"{name} does not contain a JSON object")
        return data

    project = _validate_record(Project, _get_json("project.json"), "project.json")
    repo.create_project(project)

    counts = {"scans": 0, "findings": 0, "assets": 0, "evidence": 0, "imports": 0}
    for name, member in sorted(by_name.items()):
        if name.startswith("scans/") and name.endswith(".json"):
            repo.create_scan(_validate_record(ScanJob, json.loads(member.data), name))
            counts["scans"] += 1
        elif name.startswith("findings/") and name.endswith(".json"):
            repo.create_finding(_validate_record(Finding, json.loads(member.data), name))
            counts["findings"] += 1
        elif name.startswith("assets/") and name.endswith(".json"):
            repo.create_asset(_validate_record(Asset, json.loads(member.data), name))
            counts["assets"] += 1
        elif name.startswith("evidence/") and name.endswith(".json"):
            meta = _validate_record(EvidenceMetadata, json.loads(member.data), name)
            blob_name = name[: -len(".json")] + ".bin"
            blob_member = by_name.get(blob_name)
            blob = blob_member.data if blob_member is not None else None
            repo.save_evidence(meta, blob)
            counts["evidence"] += 1
        elif name.endswith("/import.json") and name.startswith("imports/"):
            artifact = _validate_record(ImportArtifact, json.loads(member.data), name)
            raw_name = name[: -len("import.json")] + "raw.bin"
            raw_blob = by_name.get(raw_name)
            if raw_blob is None:
                raise ValidationFailedError(f"backup archive is missing {raw_name}")
            repo.create_import(artifact, raw_blob.data)
            counts["imports"] += 1

    return RestoreResult(project_id=manifest.project_id, counts=counts)
