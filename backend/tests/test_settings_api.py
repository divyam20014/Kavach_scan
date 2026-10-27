"""Phase 11: HTTP routes for settings, integrations and the CVE catalog."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.storage.repository import StorageRepository

# ---------------------------------------------------------------- settings


def test_get_settings_returns_defaults(client: TestClient) -> None:
    body = client.get("/api/settings").json()
    assert body["integrations"] == {
        "nmap_path": "",
        "sslyze_path": "",
        "testssl_path": "",
        "zap_path": "",
        "semgrep_path": "",
        "gitleaks_path": "",
        "trivy_path": "",
        "docker_path": "",
        "git_path": "",
        "online_lookup_credential_alias": "",
    }


def test_patch_settings_updates_a_tool_path_and_audits_tool_config_changed(
    client: TestClient,
) -> None:
    resp = client.patch("/api/settings", json={"integrations": {"nmap_path": sys.executable}})
    assert resp.status_code == 200
    assert resp.json()["integrations"]["nmap_path"] == sys.executable
    audit = client.get("/api/audit").json()
    assert any(e["action"] == "tool_config_changed" for e in audit["items"])


def test_patch_settings_accepts_every_tool_path_field_the_integrations_page_sends(
    client: TestClient,
) -> None:
    """Regression (TBD-087): `IntegrationsSettingsUpdate` had never been extended with
    `zap_path`/`semgrep_path`/`gitleaks_path` after they were added to the settings model
    (TBD-079/084/085) -- since the DTO is `extra='forbid'`, sending any of them (exactly
    what the Integrations page's own Save button always does, TBD-081/082) made the WHOLE
    settings PATCH fail with 422, not just that one field being silently ignored."""
    resp = client.patch(
        "/api/settings",
        json={
            "integrations": {
                "nmap_path": sys.executable,
                "zap_path": sys.executable,
                "semgrep_path": sys.executable,
                "gitleaks_path": sys.executable,
                "trivy_path": sys.executable,
                "docker_path": sys.executable,
                "git_path": sys.executable,
            }
        },
    )
    assert resp.status_code == 200
    integ = resp.json()["integrations"]
    assert integ["zap_path"] == sys.executable
    assert integ["semgrep_path"] == sys.executable
    assert integ["gitleaks_path"] == sys.executable
    assert integ["trivy_path"] == sys.executable
    assert integ["docker_path"] == sys.executable
    assert integ["git_path"] == sys.executable


def test_patch_settings_rejects_a_relative_tool_path(client: TestClient) -> None:
    resp = client.patch("/api/settings", json={"integrations": {"nmap_path": "relative/nmap"}})
    assert resp.status_code == 422


def test_patch_settings_rejects_a_raw_credential_value(client: TestClient) -> None:
    # Built from fragments at runtime (never a single secret-shaped literal in source) so a
    # secret scanner never mistakes this synthetic test value for a real provider credential.
    not_a_real_key = "-".join(("not", "a", "real", "credential", "fedcba9876543210"))
    resp = client.patch(
        "/api/settings",
        json={"integrations": {"online_lookup_credential_alias": not_a_real_key}},
    )
    assert resp.status_code == 422


def test_patch_settings_accepts_a_valid_credential_alias_and_it_round_trips(
    client: TestClient,
) -> None:
    resp = client.patch(
        "/api/settings",
        json={"integrations": {"online_lookup_credential_alias": "env:MY_KEY"}},
    )
    assert resp.status_code == 200
    assert resp.json()["integrations"]["online_lookup_credential_alias"] == "env:MY_KEY"
    # the settings-read API returns exactly what was stored: a reference, never a raw secret
    assert (
        client.get("/api/settings").json()["integrations"]["online_lookup_credential_alias"]
        == "env:MY_KEY"
    )


def test_patch_settings_honors_expected_revision_conflict(client: TestClient) -> None:
    current = client.get("/api/settings").json()
    stale_revision = current["revision"]
    client.patch("/api/settings", json={"product_name": "First change"})
    resp = client.patch(
        "/api/settings",
        json={"product_name": "Second change", "expected_revision": stale_revision},
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------- integrations


def test_integrations_list_never_shows_green_success_for_an_unverified_tool(
    client: TestClient,
) -> None:
    client.patch("/api/settings", json={"integrations": {"nmap_path": sys.executable}})
    statuses = {s["id"]: s for s in client.get("/api/integrations").json()}
    assert statuses["nmap"]["status"] == "detected"
    assert statuses["nmap"]["status"] != "verified"


def test_integration_selftest_verifies_a_real_executable_and_audits_it(
    client: TestClient,
) -> None:
    client.patch("/api/settings", json={"integrations": {"sslyze_path": sys.executable}})
    resp = client.post("/api/integrations/sslyze/selftest")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "verified"
    assert body["version"]
    audit = client.get("/api/audit").json()
    assert any(e["action"] == "integration_selftest_run" for e in audit["items"])


def test_integration_selftest_unknown_tool_is_404(client: TestClient) -> None:
    resp = client.post("/api/integrations/not-a-real-tool/selftest")
    assert resp.status_code == 404


def test_integration_selftest_missing_binary_is_not_a_false_pass(client: TestClient) -> None:
    resp = client.post("/api/integrations/testssl.sh/selftest")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] in ("not_configured", "not_found")
    assert body["version"] == ""


# ---------------------------------------------------------------- Trivy vulnerability database


def test_trivy_db_status_is_none_before_any_download(client: TestClient) -> None:
    resp = client.get("/api/integrations/trivy/db-status")
    assert resp.status_code == 200
    assert resp.json() is None


def test_download_trivy_db_cleanly_errors_when_trivy_is_not_available(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    monkeypatch.setattr(settings_api, "find_tool", lambda configured, names: "")
    resp = client.post("/api/integrations/trivy/download-db")
    assert resp.status_code == 422
    assert client.get("/api/integrations/trivy/db-status").json() is None


def test_download_trivy_db_falls_back_to_the_pulled_docker_image_when_no_native_trivy(
    client: TestClient, repo: StorageRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: an operator who only ever pulled Trivy's Docker image (never installed
    it natively) previously had no way to trigger this download at all -- the route only
    ever looked for a native `trivy` executable. Confirmed directly against a second real
    Docker invocation (TBD-095) that `fs . --download-db-only --cache-dir <dir>` genuinely
    downloads the database into the mounted cache; the real network fetch itself is mocked
    here to a no-op for the automated suite."""
    import app.api.settings as settings_api
    from app.models.docker_image import DockerImageStatusRecord

    client.patch("/api/settings", json={"integrations": {"docker_path": sys.executable}})
    # No native trivy_path set, no docker image pulled yet: still cleanly rejected.
    resp = client.post("/api/integrations/trivy/download-db")
    assert resp.status_code == 422

    repo.save_docker_image_status(
        "trivy", DockerImageStatusRecord(image="aquasec/trivy:0.76.1", verified_version="0.76.1")
    )
    monkeypatch.setattr(
        settings_api,
        "build_trivy_db_download_docker_argv",
        lambda executable, image, cache_dir: [executable, "-c", "pass"],
    )
    monkeypatch.setattr(
        settings_api,
        "build_verify_argv",
        lambda executable, engine: [executable, "-c", "print('0.76.1')"],
    )
    resp = client.post("/api/integrations/trivy/download-db")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trivy_version"] == "0.76.1"

    status = client.get("/api/integrations/trivy/db-status").json()
    assert status["trivy_version"] == "0.76.1"


def test_download_trivy_db_runs_the_real_argv_and_saves_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The *download* argv is mocked to a true no-op (no real 1.6 GB fetch in the automated
    suite, see TBD-086/087's own live verification for the real invocation); the follow-up
    `--version` call is real (`python --version`, harmless) to prove the real version-
    parsing/status-saving path end to end."""
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api,
        "build_download_db_argv",
        lambda executable, cache_dir: [executable, "-c", "pass"],
    )
    resp = client.post("/api/integrations/trivy/download-db")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trivy_version"]
    assert body["downloaded_at"]

    status = client.get("/api/integrations/trivy/db-status").json()
    assert status["trivy_version"] == body["trivy_version"]

    audit = client.get("/api/audit").json()
    assert any(e["action"] == "trivy_db_downloaded" for e in audit["items"])


def test_download_trivy_db_reports_a_clean_error_on_nonzero_exit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api,
        "build_download_db_argv",
        lambda executable, cache_dir: [executable, "-c", "import sys; sys.exit(1)"],
    )
    resp = client.post("/api/integrations/trivy/download-db")
    assert resp.status_code == 422
    assert client.get("/api/integrations/trivy/db-status").json() is None


def test_docker_image_status_is_none_before_any_pull(client: TestClient) -> None:
    resp = client.get("/api/integrations/docker/semgrep/image-status")
    assert resp.status_code == 200
    assert resp.json() is None


def test_docker_image_status_rejects_an_unknown_engine(client: TestClient) -> None:
    resp = client.get("/api/integrations/docker/nuclei/image-status")
    assert resp.status_code == 404


def test_pull_docker_image_cleanly_errors_when_docker_is_not_available(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    monkeypatch.setattr(settings_api, "find_tool", lambda configured, names: "")
    resp = client.post("/api/integrations/docker/semgrep/pull-image")
    assert resp.status_code == 422
    assert client.get("/api/integrations/docker/semgrep/image-status").json() is None


def test_pull_docker_image_rejects_an_unknown_engine(client: TestClient) -> None:
    resp = client.post("/api/integrations/docker/nuclei/pull-image")
    assert resp.status_code == 404


def test_pull_docker_image_runs_the_real_argv_and_saves_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The *pull* and *verify* argvs are mocked to true no-ops (no real network fetch of a
    400+ MB image in the automated suite; see TBD-091's own live verification for the real
    invocations). The `docker image inspect` call is left real (against `sys.executable`,
    which cannot understand it) to prove the route degrades safely -- `size_bytes`/`digest`
    default to 0/"" rather than ever failing the whole request over cosmetic metadata."""
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"docker_path": sys.executable}})
    monkeypatch.setattr(
        settings_api, "build_pull_argv", lambda executable, engine: [executable, "-c", "pass"]
    )
    monkeypatch.setattr(
        settings_api,
        "build_verify_argv",
        lambda executable, engine: [executable, "-c", "print('1.182.1')"],
    )
    resp = client.post("/api/integrations/docker/semgrep/pull-image")
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified_version"] == "1.182.1"
    assert body["image"] == "semgrep/semgrep:1.182.1"
    assert body["size_bytes"] == 0  # the real `docker image inspect` call failed harmlessly

    status = client.get("/api/integrations/docker/semgrep/image-status").json()
    assert status["verified_version"] == "1.182.1"

    audit = client.get("/api/audit").json()
    assert any(e["action"] == "docker_image_pulled" for e in audit["items"])


def test_pull_docker_image_reports_a_clean_error_on_nonzero_pull_exit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"docker_path": sys.executable}})
    monkeypatch.setattr(
        settings_api,
        "build_pull_argv",
        lambda executable, engine: [executable, "-c", "import sys; sys.exit(1)"],
    )
    resp = client.post("/api/integrations/docker/semgrep/pull-image")
    assert resp.status_code == 422
    assert client.get("/api/integrations/docker/semgrep/image-status").json() is None


def test_pull_docker_image_reports_a_clean_error_when_verification_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pull can succeed while the image still does not run correctly in this environment
    (e.g. a platform mismatch) -- this must never be recorded as a ready image."""
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"docker_path": sys.executable}})
    monkeypatch.setattr(
        settings_api, "build_pull_argv", lambda executable, engine: [executable, "-c", "pass"]
    )
    monkeypatch.setattr(
        settings_api,
        "build_verify_argv",
        lambda executable, engine: [executable, "-c", "import sys; sys.exit(1)"],
    )
    resp = client.post("/api/integrations/docker/semgrep/pull-image")
    assert resp.status_code == 422
    assert client.get("/api/integrations/docker/semgrep/image-status").json() is None


def test_remove_docker_image_status_clears_it(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"docker_path": sys.executable}})
    monkeypatch.setattr(
        settings_api, "build_pull_argv", lambda executable, engine: [executable, "-c", "pass"]
    )
    monkeypatch.setattr(
        settings_api,
        "build_verify_argv",
        lambda executable, engine: [executable, "-c", "print('1.182.1')"],
    )
    client.post("/api/integrations/docker/semgrep/pull-image")
    assert client.get("/api/integrations/docker/semgrep/image-status").json() is not None
    resp = client.delete("/api/integrations/docker/semgrep/image-status")
    assert resp.status_code == 204
    assert client.get("/api/integrations/docker/semgrep/image-status").json() is None


def test_remove_docker_image_status_rejects_an_unknown_engine(client: TestClient) -> None:
    resp = client.delete("/api/integrations/docker/nuclei/image-status")
    assert resp.status_code == 404


def test_remove_trivy_db_status_clears_it(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api,
        "build_download_db_argv",
        lambda executable, cache_dir: [executable, "-c", "pass"],
    )
    client.post("/api/integrations/trivy/download-db")
    assert client.get("/api/integrations/trivy/db-status").json() is not None
    resp = client.delete("/api/integrations/trivy/db-status")
    assert resp.status_code == 204
    assert client.get("/api/integrations/trivy/db-status").json() is None


# ---------------------------------------------------------------- Trivy IaC checks bundle


def _fake_checks_argv_that_populates_the_cache(executable: str, cache_dir: Path) -> list[str]:
    code = (
        "import pathlib, sys\n"
        "p = pathlib.Path(sys.argv[1]) / 'policy' / 'content'\n"
        "p.mkdir(parents=True, exist_ok=True)\n"
        "(p / 'marker').write_text('x')\n"
    )
    return [executable, "-c", code, str(cache_dir)]


def test_trivy_checks_status_is_none_before_any_download(client: TestClient) -> None:
    resp = client.get("/api/integrations/trivy/checks-status")
    assert resp.status_code == 200
    assert resp.json() is None


def test_download_trivy_checks_cleanly_errors_when_trivy_is_not_available(
    client: TestClient,
) -> None:
    resp = client.post("/api/integrations/trivy/download-checks")
    assert resp.status_code == 422


def test_download_trivy_checks_runs_the_real_argv_and_saves_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api, "build_download_checks_argv", _fake_checks_argv_that_populates_the_cache
    )
    resp = client.post("/api/integrations/trivy/download-checks")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trivy_version"]
    assert body["downloaded_at"]

    status = client.get("/api/integrations/trivy/checks-status").json()
    assert status["trivy_version"] == body["trivy_version"]

    audit = client.get("/api/audit").json()
    assert any(e["action"] == "trivy_checks_downloaded" for e in audit["items"])


def test_download_trivy_checks_rejects_a_silent_fallback_to_embedded_checks(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Confirmed directly (TBD-111): Trivy's own checks-bundle download can exit 0 while
    silently falling back to embedded checks on a network failure -- this must never be
    recorded as a successful download just because the process exited cleanly."""
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api,
        "build_download_checks_argv",
        lambda executable, cache_dir: [executable, "-c", "pass"],  # exits 0, creates nothing
    )
    resp = client.post("/api/integrations/trivy/download-checks")
    assert resp.status_code == 422
    assert client.get("/api/integrations/trivy/checks-status").json() is None


def test_download_trivy_checks_reports_a_clean_error_on_nonzero_exit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api,
        "build_download_checks_argv",
        lambda executable, cache_dir: [executable, "-c", "import sys; sys.exit(1)"],
    )
    resp = client.post("/api/integrations/trivy/download-checks")
    assert resp.status_code == 422
    assert client.get("/api/integrations/trivy/checks-status").json() is None


def test_remove_trivy_checks_status_clears_it(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.settings as settings_api

    client.patch("/api/settings", json={"integrations": {"trivy_path": sys.executable}})
    monkeypatch.setattr(
        settings_api, "build_download_checks_argv", _fake_checks_argv_that_populates_the_cache
    )
    client.post("/api/integrations/trivy/download-checks")
    assert client.get("/api/integrations/trivy/checks-status").json() is not None
    resp = client.delete("/api/integrations/trivy/checks-status")
    assert resp.status_code == 204
    assert client.get("/api/integrations/trivy/checks-status").json() is None


# ---------------------------------------------------------------- CVE catalog


def _catalog_bytes() -> bytes:
    import json

    return json.dumps(
        {
            "source": "Test catalog",
            "catalog_version": "1.0",
            "entries": [
                {"product": "jquery", "version_spec": "<1.12.4", "cve_id": "CVE-2015-9251"}
            ],
        }
    ).encode()


def test_cve_catalog_is_none_before_import(client: TestClient) -> None:
    resp = client.get("/api/cve-catalog")
    assert resp.status_code == 200
    assert resp.json() is None


def test_cve_catalog_import_preview_and_delete_round_trip(
    client: TestClient,
    repo: StorageRepository,
) -> None:
    resp = client.post(
        "/api/cve-catalog/import",
        files={"file": ("catalog.json", _catalog_bytes(), "application/json")},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["entry_count"] == 1
    assert body["is_stale"] is False
    assert len(body["file_sha256"]) == 64

    status_resp = client.get("/api/cve-catalog").json()
    assert status_resp["catalog_version"] == "1.0"

    audit = client.get("/api/audit").json()
    assert any(e["action"] == "cve_catalog_imported" for e in audit["items"])

    delete_resp = client.delete("/api/cve-catalog")
    assert delete_resp.status_code == 204
    assert client.get("/api/cve-catalog").json() is None


def test_cve_catalog_import_rejects_malformed_json(client: TestClient) -> None:
    resp = client.post(
        "/api/cve-catalog/import",
        files={"file": ("bad.json", b"not json", "application/json")},
    )
    assert resp.status_code == 422


def test_cve_catalog_import_rejects_an_oversized_file(client: TestClient) -> None:
    import app.api.settings as settings_api

    old = settings_api.MAX_CATALOG_BYTES
    settings_api.MAX_CATALOG_BYTES = 10
    try:
        resp = client.post(
            "/api/cve-catalog/import",
            files={"file": ("catalog.json", _catalog_bytes(), "application/json")},
        )
        assert resp.status_code == 422
    finally:
        settings_api.MAX_CATALOG_BYTES = old


def test_cve_catalog_shows_stale_after_the_configured_window(
    client: TestClient,
    repo: StorageRepository,
) -> None:
    from datetime import timedelta

    from app.cve.parser import parse_catalog_file
    from app.models.common import utc_now

    record = parse_catalog_file(_catalog_bytes())
    stale = record.model_copy(
        update={
            "stale_after_days": 1,
            "imported_at": utc_now() - timedelta(days=5),
        }
    )
    repo.save_cve_catalog(stale)
    body = client.get("/api/cve-catalog").json()
    assert body["is_stale"] is True
