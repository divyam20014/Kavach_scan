"""Phase 11: HTTP routes for settings, integrations and the CVE catalog."""

from __future__ import annotations

import sys

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
