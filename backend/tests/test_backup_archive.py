"""Phase 10: project backup export/preview/restore, and archive safety."""

from __future__ import annotations

import io
import zipfile

import pytest

from app.backup.archive import export_archive, preview_archive, restore_archive
from app.backup.safety import ArchiveSafetyError, safe_extract_all
from app.core.errors import ConflictError, ValidationFailedError
from app.models.evidence import EvidenceMetadata
from app.storage.repository import StorageRepository
from tests.conftest import make_asset, make_finding
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def _make_zip(entries: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _unpack(archive: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def _repack(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _retamper_with_valid_checksum(archive: bytes, name: str, new_data: bytes) -> bytes:
    """Replace one member's content and recompute its manifest checksum, so the tampering
    under test is the *content itself* (e.g. a forged project_id), not merely a checksum
    mismatch that a separate, already-covered test exercises."""
    import hashlib
    import json

    members = _unpack(archive)
    members[name] = new_data
    manifest = json.loads(members["manifest.json"])
    manifest["checksums"][name] = hashlib.sha256(new_data).hexdigest()
    members["manifest.json"] = json.dumps(manifest).encode("utf-8")
    return _repack(members)


# ---------------------------------------------------------------- safety


def test_safe_extract_all_rejects_path_traversal() -> None:
    with pytest.raises(ArchiveSafetyError, match="unsafe path"):
        safe_extract_all(_make_zip({"../../etc/passwd": "pwned"}))


def test_safe_extract_all_rejects_absolute_and_drive_paths() -> None:
    with pytest.raises(ArchiveSafetyError, match="unsafe"):
        safe_extract_all(_make_zip({"/etc/passwd": "pwned"}))
    with pytest.raises(ArchiveSafetyError, match="unsafe"):
        safe_extract_all(_make_zip({"C:/Windows/evil.dll": "pwned"}))


def test_safe_extract_all_rejects_symlink_entries() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ArchiveSafetyError, match="symlink"):
        safe_extract_all(buf.getvalue())


def test_safe_extract_all_rejects_nested_archives() -> None:
    inner = _make_zip({"x.txt": "1"})
    outer = _make_zip({"inner.zip": inner})
    with pytest.raises(ArchiveSafetyError, match="nested"):
        safe_extract_all(outer)


def test_safe_extract_all_rejects_oversized_declared_expansion() -> None:
    import app.backup.safety as safety_mod

    old = safety_mod.MAX_EXPANDED_BYTES
    safety_mod.MAX_EXPANDED_BYTES = 10
    try:
        with pytest.raises(ArchiveSafetyError, match="declared uncompressed size"):
            safe_extract_all(_make_zip({"big.txt": "0" * 1000}))
    finally:
        safety_mod.MAX_EXPANDED_BYTES = old


def test_safe_extract_all_rejects_too_many_entries() -> None:
    import app.backup.safety as safety_mod

    old = safety_mod.MAX_ENTRIES
    safety_mod.MAX_ENTRIES = 2
    try:
        with pytest.raises(ArchiveSafetyError, match="more than"):
            safe_extract_all(_make_zip({"a": "1", "b": "1", "c": "1"}))
    finally:
        safety_mod.MAX_ENTRIES = old


def test_safe_extract_all_rejects_garbage_input() -> None:
    with pytest.raises(ArchiveSafetyError, match="not a valid ZIP"):
        safe_extract_all(b"not a zip file at all")


def test_safe_extract_all_accepts_a_normal_archive() -> None:
    members = safe_extract_all(_make_zip({"a/b.json": "{}", "c.txt": "hi"}))
    assert {m.name for m in members} == {"a/b.json", "c.txt"}


# ---------------------------------------------------------------- export/restore round trip


def test_export_preview_restore_round_trip_preserves_counts_and_evidence_links(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid, title="F1"))
    repo.create_asset(make_asset(pid))
    ev = repo.save_evidence(
        EvidenceMetadata(
            evidence_id="evd_" + "1" * 32,
            project_id=pid,
            finding_ids=[f.finding_id],
            evidence_type="text_excerpt",
            request_excerpt="req",
            response_excerpt="resp",
        ),
        blob=b"raw evidence bytes",
    )
    archive = export_archive(repo, pid, include_evidence_blobs=True)

    # restore into a clean, separate data directory (not the same repo)
    import tempfile

    from app.core.settings import RuntimeSettings
    from app.storage.repository import StorageRepository as Repo

    tmp = tempfile.mkdtemp()
    clean_repo = Repo.open(RuntimeSettings(data_dir=tmp + "/data"))
    try:
        preview = preview_archive(clean_repo, archive)
        assert preview.project_already_exists is False
        assert preview.checksum_mismatches == []
        assert preview.counts == {
            "scans": 0,
            "findings": 1,
            "assets": 1,
            "evidence": 1,
            "imports": 0,
        }

        result = restore_archive(clean_repo, archive, confirmed=True)
        assert result.project_id == pid
        assert clean_repo.list_findings(pid).total == repo.list_findings(pid).total == 1
        assert clean_repo.list_assets(pid).total == repo.list_assets(pid).total == 1
        restored_ev = clean_repo.get_evidence(pid, ev.evidence_id)
        assert restored_ev.finding_ids == [f.finding_id]
        assert clean_repo.read_evidence_blob(pid, ev.evidence_id) == b"raw evidence bytes"
    finally:
        clean_repo.close()


def test_restore_without_confirmation_is_rejected(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    archive = export_archive(repo, pid)
    with pytest.raises(ValidationFailedError):
        restore_archive(repo, archive, confirmed=False)


def test_restore_into_a_colliding_project_id_requires_overwrite(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="Original"))
    archive = export_archive(repo, pid)

    with pytest.raises(ConflictError):
        restore_archive(repo, archive, confirmed=True, overwrite=False)
    # current data is preserved exactly (acceptance criterion)
    assert repo.list_findings(pid).items[0].title == "Original"

    result = restore_archive(repo, archive, confirmed=True, overwrite=True)
    assert result.project_id == pid
    assert repo.list_findings(pid).total == 1


def test_restore_rejects_a_tampered_checksum(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    archive = export_archive(repo, pid)
    members = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        for name in zf.namelist():
            members[name] = zf.read(name)
    # tamper with a finding record after it was checksummed
    for name in list(members):
        if name.startswith("findings/"):
            members[name] = members[name].replace(b'"title"', b'"tampered"')
    tampered = io.BytesIO()
    with zipfile.ZipFile(tampered, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)

    import tempfile

    from app.core.settings import RuntimeSettings
    from app.storage.repository import StorageRepository as Repo

    tmp = tempfile.mkdtemp()
    clean_repo = Repo.open(RuntimeSettings(data_dir=tmp + "/data"))
    try:
        with pytest.raises(ValidationFailedError, match="checksum"):
            restore_archive(clean_repo, tampered.getvalue(), confirmed=True)
    finally:
        clean_repo.close()


def test_preview_never_writes_anything(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    archive = export_archive(repo, pid)
    preview_archive(repo, archive)  # same repo, project already exists
    assert repo.list_findings(pid).total == 1  # unchanged, nothing duplicated


def test_export_can_exclude_evidence_blobs(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    ev = repo.save_evidence(
        EvidenceMetadata(
            evidence_id="evd_" + "2" * 32,
            project_id=pid,
            finding_ids=[f.finding_id],
            evidence_type="text_excerpt",
            request_excerpt="req",
            response_excerpt="resp",
        ),
        blob=b"secret-looking blob data",
    )
    archive = export_archive(repo, pid, include_evidence_blobs=False)
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        names = zf.namelist()
    assert f"evidence/{ev.evidence_id}.json" in names
    assert f"evidence/{ev.evidence_id}.bin" not in names


def test_restore_rejects_an_unsupported_manifest_schema_version(repo: StorageRepository) -> None:
    bad = _make_zip({"manifest.json": '{"schema_version": 999}'})
    with pytest.raises(ValidationFailedError, match="schema_version"):
        restore_archive(repo, bad, confirmed=True)


def test_restore_rejects_a_malicious_archive_before_touching_storage(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    before = repo.list_findings(pid).total
    repo.create_finding(make_finding(pid))
    malicious = _make_zip({"../../etc/passwd": "pwned", "manifest.json": "{}"})
    with pytest.raises(ValidationFailedError, match="unsafe path"):
        restore_archive(repo, malicious, confirmed=True)
    # the attempted attack writes nothing; the project's own data is untouched
    assert repo.list_findings(pid).total == before + 1


# ---------------------------------------------------------------- record/project-id integrity


def test_restore_rejects_a_finding_whose_project_id_does_not_match_the_archive(
    repo: StorageRepository,
) -> None:
    """A crafted archive could otherwise smuggle a record into a *different*, already-existing
    project in the destination data directory, since the storage layer writes each record to
    whatever `project_id` field it carries, not to "the project being restored"."""
    victim_pid = _project(repo)  # already exists in the destination repo
    victim_findings_before = repo.list_findings(victim_pid).total

    attacker_pid = _project(repo)
    f = repo.create_finding(make_finding(attacker_pid, title="Smuggled"))
    archive = export_archive(repo, attacker_pid)

    import json

    members = _unpack(archive)
    finding_name = f"findings/{f.finding_id}.json"
    record = json.loads(members[finding_name])
    record["project_id"] = victim_pid  # forged: point at the OTHER, existing project
    tampered = _retamper_with_valid_checksum(
        archive, finding_name, json.dumps(record).encode("utf-8")
    )

    with pytest.raises(ValidationFailedError, match="project_id"):
        restore_archive(repo, tampered, confirmed=True)

    # nothing was smuggled into the victim project, and nothing else was written either
    assert repo.list_findings(victim_pid).total == victim_findings_before


def test_restore_rejects_a_manifest_whose_project_id_disagrees_with_project_json(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    archive = export_archive(repo, pid)

    import json

    members = _unpack(archive)
    manifest = json.loads(members["manifest.json"])
    manifest["project_id"] = "prj_" + "9" * 32  # does not match project.json's own id
    import hashlib

    new_manifest_bytes = json.dumps(manifest).encode("utf-8")
    members["manifest.json"] = new_manifest_bytes
    tampered = _repack(members)
    # manifest.json itself is not in its own checksums dict, so no checksum step is needed.

    with pytest.raises(ValidationFailedError, match="project_id"):
        restore_archive(repo, tampered, confirmed=True)
    assert hashlib.sha256(new_manifest_bytes).hexdigest()  # sanity: bytes were actually changed


def test_preview_also_reports_project_id_inconsistencies_without_writing(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    archive = export_archive(repo, pid)

    import json

    members = _unpack(archive)
    finding_name = f"findings/{f.finding_id}.json"
    record = json.loads(members[finding_name])
    record["project_id"] = "prj_" + "8" * 32
    tampered = _retamper_with_valid_checksum(
        archive, finding_name, json.dumps(record).encode("utf-8")
    )

    import tempfile

    from app.core.settings import RuntimeSettings
    from app.storage.repository import StorageRepository as Repo

    tmp = tempfile.mkdtemp()
    clean_repo = Repo.open(RuntimeSettings(data_dir=tmp + "/data"))
    try:
        preview = preview_archive(clean_repo, tampered)
        assert any("project_id" in m for m in preview.checksum_mismatches)
        assert preview.project_already_exists is False
        with pytest.raises(Exception, match="not found"):
            clean_repo.get_project(pid)  # preview never creates the project
    finally:
        clean_repo.close()


def test_restore_rejects_a_project_json_that_fails_schema_validation(
    repo: StorageRepository,
) -> None:
    """A `Project.model_validate` failure on fully attacker-controlled bytes must become a
    clean validation error, never an unhandled exception."""
    bad = _make_zip(
        {
            "manifest.json": (
                '{"schema_version": 1, "exported_at": "x", "app_version": "x", '
                '"storage_version": 1, "project_id": "prj_' + "1" * 32 + '", '
                '"include_evidence_blobs": true, "counts": {}, "checksums": {}}'
            ),
            "project.json": '{"not": "a project"}',
        }
    )
    with pytest.raises(ValidationFailedError, match="project.json"):
        restore_archive(repo, bad, confirmed=True)


# ---------------------------------------------------------------- corrupt/tampered archives


def test_safe_extract_all_rejects_a_corrupt_entry_cleanly() -> None:
    """A bit-flipped/corrupt DEFLATE stream must be rejected as ArchiveSafetyError, never an
    unhandled zipfile.BadZipFile propagating out of this module."""
    raw = bytearray(_make_zip({"findings/x.json": "{}" * 2000}))
    # flip a byte well inside the compressed data region (past the local file header) to
    # corrupt the DEFLATE stream without touching the ZIP structure itself.
    local_header_end = raw.find(b"PK\x03\x04") + 30 + len(b"findings/x.json")
    raw[local_header_end + 5] ^= 0xFF
    with pytest.raises(ArchiveSafetyError):
        safe_extract_all(bytes(raw))
