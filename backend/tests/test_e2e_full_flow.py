"""Phase 12: one full local end-to-end flow through the real HTTP API, entirely offline
against local fixtures — the acceptance criterion's explicit checklist:

    create project -> configure scope -> safe web scan -> map assets (surface scan) ->
    inventory an API spec -> run a safe API baseline scan -> import Nmap/Nuclei/SARIF
    fixtures -> triage/dedupe -> generate HTML/PDF -> export/restore -> restart and
    verify persisted data.

Everything here goes through `client` (the real FastAPI app, real JobManager, real scope
engine) — no shortcuts through internal service functions except where the application
itself has no HTTP route for something (there is none for "restart the process", which is
simulated by closing and reopening a `StorageRepository` against the same data directory).
"""

from __future__ import annotations

import io
import json
import tempfile
import time
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.main import create_app
from app.models.project import ScopeDefinition
from app.scope.engine import scope_hash
from app.storage.repository import StorageRepository
from tests import importfixtures as fx
from tests.apifixtures import ApiHandler, start_api
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT
from tests.webfixtures import lab_servers

NOW = datetime.now(UTC)


def _preview_hash(scope: dict[str, Any]) -> str:
    return scope_hash(ScopeDefinition.model_validate(scope))


def _wait(client: TestClient, pid: str, sid: str, timeout: float = 90) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/projects/{pid}/scans/{sid}").json()
        if body["terminal"]:
            return body  # type: ignore[no-any-return]
        time.sleep(0.1)
    raise AssertionError(f"scan {sid} did not finish in {timeout}s")


def test_full_local_application_flow(settings: RuntimeSettings) -> None:
    api_server = start_api()
    try:
        _e2e_flow(settings, api_server)
    finally:
        api_server.shutdown()
        api_server.server_close()


def _e2e_flow(settings: RuntimeSettings, api_server: Any) -> None:
    with lab_servers() as (lab_port, _victim_port):
        api_port = api_server.server_address[1]
        app = create_app(settings)
        with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as client:
            # ---------------------------------------------------------------- 1. create project

            scope = {
                "schemes": ["http"],
                "hosts": [],
                "ip_ranges": ["127.0.0.1/32"],
                "ports": [lab_port, api_port],
                "path_prefixes": ["/"],
            }
            body = {
                "name": "E2E Assessment",
                "client_name": "Acme Corp",
                "authorization": {
                    "organization": "Acme Corp", "target_owner": "Acme IT",
                    "authorized_by": "CISO Jane Doe",
                    "window_start": (NOW - timedelta(days=1)).isoformat(),
                    "window_end": (NOW + timedelta(days=30)).isoformat(),
                    "attestation": True,
                },
                "scope": scope,
                "scope_preview_hash": _preview_hash(scope),
                "scan_policy": {
                    "allowed_modules": ["web_app", "attack_surface", "api_security"],
                    "requests_per_second": 10, "max_concurrency": 4, "max_pages": 50,
                },
            }
            created = client.post("/api/projects", json=body)
            assert created.status_code == 201, created.text
            project = created.json()
            pid = project["project_id"]

            # ---------------------------------------------------------------- 2. configure scope
            # (internal-target override: 127.0.0.1 is blocked by default — Phase 03)

            override = client.put(
                f"/api/projects/{pid}/internal-override",
                json={
                    "expected_revision": project["revision"],
                    "ip_ranges": ["127.0.0.1/32"],
                    "reason": "e2e fixture lab",
                    "expires_at": (NOW + timedelta(hours=2)).isoformat(),
                    "attestation": True,
                },
            )
            assert override.status_code == 200, override.text

            # ---------------------------------------------------------------- 3. safe web scan

            web_scan = client.post(
                f"/api/projects/{pid}/scans",
                json={
                    "module": "web_app", "confirmed": True,
                    "targets": [f"http://127.0.0.1:{lab_port}/"], "parameters": {},
                },
            )
            assert web_scan.status_code == 202, web_scan.text
            web_done = _wait(client, pid, web_scan.json()["scan_id"])
            assert web_done["scan"]["state"] in ("completed", "completed_with_warnings"), web_done

            # ---------------------------------------------------------------- 4. map assets (surface)

            surface_scan = client.post(
                f"/api/projects/{pid}/scans",
                json={
                    "module": "attack_surface", "confirmed": True,
                    "targets": ["127.0.0.1"],
                    "parameters": {"ports": f"{lab_port},{api_port}"},
                },
            )
            assert surface_scan.status_code == 202, surface_scan.text
            surface_done = _wait(client, pid, surface_scan.json()["scan_id"])
            assert surface_done["scan"]["state"] in ("completed", "completed_with_warnings"), surface_done
            assets = client.get("/api/assets", params={"project_id": pid}).json()
            assert assets["total"] >= 1

            # ---------------------------------------------------------------- 5. inventory an API spec

            spec_doc = {
                "openapi": "3.0.3",
                "info": {"title": "E2E API", "version": "1.0"},
                "servers": [{"url": f"http://127.0.0.1:{api_port}/v1"}],
                "paths": {
                    "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
                },
            }
            spec_resp = client.post(
                f"/api/projects/{pid}/api-specs",
                files={"file": ("e2e.json", json.dumps(spec_doc).encode(), "application/json")},
            )
            assert spec_resp.status_code == 201, spec_resp.text
            spec_import_id = spec_resp.json()["summary"]["import_id"]

            # ---------------------------------------------------------------- 6. safe API baseline

            requests_before_api_scan = len(ApiHandler.requests)
            api_scan = client.post(
                f"/api/projects/{pid}/scans",
                json={
                    "module": "api_security", "confirmed": True, "targets": ["api-spec"],
                    "parameters": {"import_id": spec_import_id, "inventory_only": True},
                },
            )
            assert api_scan.status_code == 202, api_scan.text
            api_done = _wait(client, pid, api_scan.json()["scan_id"])
            assert api_done["scan"]["state"] in ("completed", "completed_with_warnings"), api_done
            # inventory-only sends zero requests of its own (Phase 07); the surface scan's
            # own web-origin probe against the same port, run earlier, is unaffected.
            assert len(ApiHandler.requests) == requests_before_api_scan

            # ---------------------------------------------------------------- 7. import external fixtures

            for raw, filename, ctype in (
                (fx.NMAP_XML, "nmap.xml", "application/xml"),
                (fx.NUCLEI_JSONL, "nuclei.jsonl", "application/x-ndjson"),
                (fx.SARIF_JSON, "results.sarif", "application/sarif+json"),
            ):
                up = client.post(
                    f"/api/projects/{pid}/imports",
                    files={"file": (filename, raw, ctype)},
                )
                assert up.status_code == 201, (filename, up.text)
                summary = up.json()["summary"]
                commit = client.post(
                    f"/api/projects/{pid}/imports/{summary['import_id']}/commit",
                    json={"confirmed": True, "expected_revision": summary["revision"]},
                )
                assert commit.status_code == 200, (filename, commit.text)

            findings_page = client.get("/api/findings", params={"project_id": pid, "limit": 200}).json()
            assert findings_page["total"] >= 3  # at least one finding per imported fixture
            sources = {item["module"] for item in findings_page["items"]}
            assert "import" in sources

            # ---------------------------------------------------------------- 8. triage / dedupe

            first = findings_page["items"][0]["finding"]
            triaged = client.patch(
                f"/api/projects/{pid}/findings/{first['finding_id']}",
                json={
                    "expected_revision": first["revision"], "analyst_status": "confirmed",
                    "business_priority": "p2",
                },
            )
            assert triaged.status_code == 200, triaged.text
            assert triaged.json()["finding"]["analyst_status"] == "confirmed"

            second = next(
                i["finding"] for i in findings_page["items"]
                if i["finding"]["finding_id"] != first["finding_id"]
            )
            merged = client.post(
                f"/api/projects/{pid}/findings/{second['finding_id']}/merge",
                json={
                    "expected_revision": second["revision"],
                    "into_finding_id": first["finding_id"],
                },
            )
            assert merged.status_code == 200, merged.text

            # ---------------------------------------------------------------- 9. generate HTML/PDF

            report = client.post(f"/api/projects/{pid}/reports", json={"formats": ["html", "pdf"]})
            assert report.status_code == 201, report.text
            report_id = report.json()["report_id"]
            html = client.get(f"/api/projects/{pid}/reports/{report_id}/download/html")
            pdf = client.get(f"/api/projects/{pid}/reports/{report_id}/download/pdf")
            assert html.status_code == 200 and "<html" in html.text.lower()
            assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"

            # ---------------------------------------------------------------- 10. export / restore

            archive = client.get(f"/api/projects/{pid}/backup/export")
            assert archive.status_code == 200
            with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
                assert "manifest.json" in zf.namelist()
            # include_merged=true for an apples-to-apples count against the raw storage-level
            # repository reads below, which (correctly) don't filter out merged duplicates the
            # way the findings-workbench list does by default (Phase 09).
            original_finding_total = client.get(
                "/api/findings", params={"project_id": pid, "limit": 200, "include_merged": True}
            ).json()["total"]

        # end of the `with TestClient` block: the app (and its JobManager) has shut down.

    # ---------------------------------------------------------------- 11. restore into a clean root

    restore_tmp = tempfile.mkdtemp()
    restore_repo = StorageRepository.open(RuntimeSettings(data_dir=restore_tmp + "/data"))
    try:
        from app.backup.archive import restore_archive

        result = restore_archive(restore_repo, archive.content, confirmed=True)
        assert result.project_id == pid
        assert restore_repo.list_findings(pid, limit=200).total == original_finding_total
    finally:
        restore_repo.close()

    # ---------------------------------------------------------------- 12. restart; verify persistence

    reopened = StorageRepository.open(settings)
    try:
        restarted_project = reopened.get_project(pid)
        assert restarted_project.name == "E2E Assessment"
        assert reopened.list_scans(pid, limit=50).total == 3  # web + surface + api
        assert reopened.list_findings(pid, limit=200).total == original_finding_total
        assert reopened.list_reports(pid, limit=10).total == 1
    finally:
        reopened.close()
