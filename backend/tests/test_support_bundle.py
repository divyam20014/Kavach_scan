"""Phase 13: diagnostic support bundle export — redacted, no evidence blobs, and full finding
records only when explicitly requested."""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.models.evidence import EvidenceMetadata
from app.storage.repository import StorageRepository
from app.support_bundle import build_support_bundle
from tests.conftest import make_finding
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def _read_zip(archive: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def test_bundle_never_includes_evidence_blobs_or_findings_by_default(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid, title="Should not appear"))
    repo.save_evidence(
        EvidenceMetadata(
            evidence_id="evd_" + "1" * 32,
            project_id=pid,
            finding_ids=[f.finding_id],
            evidence_type="text_excerpt",
            request_excerpt="req",
            response_excerpt="resp",
        ),
        blob=b"raw evidence bytes that must never leave in a support bundle",
    )
    archive = build_support_bundle(repo, settings)
    files = _read_zip(archive)
    assert "findings" not in [n.split("/")[0] for n in files if "/" in n]
    whole = b"".join(files.values())
    assert b"raw evidence bytes" not in whole
    assert b"Should not appear" not in whole

    version = json.loads(files["version.json"])
    assert version["evidence_included"] is False
    assert version["include_findings"] is False

    projects = json.loads(files["projects.json"])
    assert projects[0]["project_id"] == pid
    assert projects[0]["counts"]["finding"] == 1  # count only, no title/body


def test_bundle_includes_redacted_findings_when_explicitly_requested(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    pid = _project(repo)
    secret = "sk_" + "live_SECRETVALUEFORTESTINGONLY0000"  # noqa: S105 - test fixture
    repo.create_finding(
        make_finding(
            pid,
            title="Leaky header",
            summary=f"Authorization: Bearer {secret}",
        )
    )
    archive = build_support_bundle(repo, settings, include_findings=True)
    files = _read_zip(archive)
    findings_files = [n for n in files if n.startswith("findings/")]
    assert findings_files == [f"findings/{pid}.json"]
    doc = json.loads(files[findings_files[0]])
    assert doc["total"] == 1 and doc["included"] == 1 and doc["truncated"] is False
    assert doc["findings"][0]["title"] == "Leaky header"
    assert secret not in files[findings_files[0]].decode()  # redacted a second time


def test_bundle_marks_findings_truncated_past_the_per_project_cap(
    repo: StorageRepository,
    settings: RuntimeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.support_bundle as support_bundle_module

    monkeypatch.setattr(support_bundle_module, "MAX_FINDINGS_PER_PROJECT", 2)
    pid = _project(repo)
    for i in range(3):
        repo.create_finding(make_finding(pid, title=f"Finding {i}"))
    archive = build_support_bundle(repo, settings, include_findings=True)
    files = _read_zip(archive)
    doc = json.loads(files[f"findings/{pid}.json"])
    assert doc["total"] == 3
    assert doc["included"] == 2
    assert doc["truncated"] is True  # never silently incomplete


def test_bundle_never_leaks_a_credential_alias_as_a_raw_secret(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    """`online_lookup_credential_alias` only ever holds a reference (`env:NAME`), never a raw
    secret (enforced at the settings-validation layer, TBD-068) — but the bundle's defensive,
    key-name-based redaction pass treats any field whose name contains "credential" as secret
    regardless of its value, which is a safe (over-cautious, never under-cautious) default."""
    from app.models.settings import IntegrationsSettings

    current = repo.get_settings()
    current.integrations = IntegrationsSettings(online_lookup_credential_alias="env:MY_KEY")
    repo.save_settings(current)
    archive = build_support_bundle(repo, settings)
    files = _read_zip(archive)
    settings_doc = json.loads(files["settings.json"])
    assert settings_doc["integrations"]["online_lookup_credential_alias"] == "[REDACTED]"
    assert b"env:MY_KEY" not in b"".join(files.values())
    assert b"sk_live_" not in b"".join(files.values())


def test_bundle_carries_version_storage_and_integration_info(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    archive = build_support_bundle(repo, settings)
    files = _read_zip(archive)
    version = json.loads(files["version.json"])
    assert version["app_version"]
    assert version["storage_version"] == 1
    diag = json.loads(files["storage_diagnostics.json"])
    assert diag["ready"] is True
    integrations = json.loads(files["integrations.json"])
    assert {i["id"] for i in integrations} == {
        "nmap",
        "sslyze",
        "testssl.sh",
        "zap",
        "semgrep",
        "gitleaks",
        "trivy",
        "docker",
        "git",
    }
    assert json.loads(files["cve_catalog.json"]) is None  # none imported


def test_bundle_api_route_requires_explicit_opt_in_for_findings_and_audits(
    client: TestClient,
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))

    default_resp = client.get("/api/diagnostics/support-bundle")
    assert default_resp.status_code == 200
    assert default_resp.headers["content-type"] == "application/zip"
    default_files = _read_zip(default_resp.content)
    assert not [n for n in default_files if n.startswith("findings/")]

    opt_in_resp = client.get("/api/diagnostics/support-bundle", params={"include_findings": True})
    assert opt_in_resp.status_code == 200
    opt_in_files = _read_zip(opt_in_resp.content)
    assert f"findings/{pid}.json" in opt_in_files

    audit = client.get("/api/audit").json()
    actions = [e["action"] for e in audit["items"]]
    assert actions.count("support_bundle_exported") == 2


def test_bundle_recent_audit_events_are_already_redacted(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    from app.models.audit import AuditAction

    pid = _project(repo)
    repo.audit.record(
        AuditAction.PROJECT_UPDATED,
        project_id=pid,
        metadata={"password": "hunter2-should-be-redacted"},
    )
    archive = build_support_bundle(repo, settings)
    files = _read_zip(archive)
    assert b"hunter2" not in b"".join(files.values())
