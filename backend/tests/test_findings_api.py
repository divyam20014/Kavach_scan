"""Phase 09: findings workbench HTTP routes, standards/risk-formula endpoints, per-finding
audit trail, and dashboard trend/click-through reconciliation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models.common import new_id
from app.storage.repository import StorageRepository
from tests.conftest import make_finding
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def test_list_findings_cross_project_with_rich_filters(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(
        make_finding(
            pid, title="Reflected XSS", severity="high", rule_id="WEB-XSS-001", cwe_ids=[79]
        )
    )
    repo.create_finding(make_finding(pid, title="Outdated jQuery", severity="low"))
    body = client.get("/api/findings", params={"project_id": pid}).json()
    assert body["total"] == 2
    item = body["items"][0]
    assert {"finding", "module", "risk_score", "risk_tier", "reviewed"} <= set(item)

    filtered = client.get(
        "/api/findings", params={"project_id": pid, "cwe": 79, "module": "web_app"}
    ).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["finding"]["title"] == "Reflected XSS"

    searched = client.get("/api/findings", params={"project_id": pid, "q": "jquery"}).json()
    assert searched["total"] == 1


def test_finding_detail_update_comment_and_audit_trail(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid, title="Missing CSP"))

    detail = client.get(f"/api/projects/{pid}/findings/{f.finding_id}").json()
    assert detail["finding"]["title"] == "Missing CSP"
    assert detail["module"] in {"web_app", "unknown"}
    assert "score" in detail["risk"] and "tier" in detail["risk"]

    resp = client.patch(
        f"/api/projects/{pid}/findings/{f.finding_id}",
        json={
            "expected_revision": 1,
            "analyst_status": "confirmed",
            "business_impact": "Exposes customer data",
            "business_priority": "p1",
        },
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["finding"]["analyst_status"] == "confirmed"
    assert updated["finding"]["business_priority"] == "p1"
    # original source data is untouched by the triage edit
    assert updated["finding"]["severity"] == f.severity.value
    assert updated["finding"]["title"] == "Missing CSP"

    commented = client.post(
        f"/api/projects/{pid}/findings/{f.finding_id}/comments",
        json={
            "text": "Confirmed via manual review",
            "expected_revision": updated["finding"]["revision"],
        },
    )
    assert commented.status_code == 200
    assert commented.json()["finding"]["comments"][0]["text"] == "Confirmed via manual review"

    audit = client.get("/api/audit", params={"target_id": f.finding_id}).json()
    actions = [e["action"] for e in audit["items"]]
    assert "finding_updated" in actions
    assert "finding_comment_added" in actions


def test_finding_evidence_is_redacted_and_a_dangling_reference_is_skipped(
    client: TestClient, repo: StorageRepository
) -> None:
    """UI/UX modernization, findings phase (TBD-106): `evidence_ids` was already on every
    `Finding` but never had a route to read it back through -- this is that route. A raw
    secret embedded in an evidence excerpt must never reach the response, and a finding
    referencing an evidence record that no longer exists must not 500 the whole detail."""
    from app.models.evidence import EvidenceMetadata

    pid = _project(repo)
    secret_fragments = ("not", "a", "real", "credential", "0123456789abcdef0123456789abcdef")
    secret = "-".join(secret_fragments)
    evidence = repo.save_evidence(
        EvidenceMetadata(
            evidence_id=new_id("evidence"),
            project_id=pid,
            evidence_type="http_exchange",
            request_excerpt=f"Cookie: session={secret}",
            response_excerpt="HTTP/1.1 200 OK",
        )
    )
    dangling_id = new_id("evidence")
    f = repo.create_finding(
        make_finding(
            pid, title="Session cookie exposed", evidence_ids=[evidence.evidence_id, dangling_id]
        )
    )

    resp = client.get(f"/api/projects/{pid}/findings/{f.finding_id}/evidence")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1  # the dangling reference was skipped, not a 500
    assert items[0]["evidence_id"] == evidence.evidence_id
    assert secret not in items[0]["request_excerpt"]
    assert items[0]["response_excerpt"] == "HTTP/1.1 200 OK"


def test_update_finding_rejects_unknown_field_and_stale_revision(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    bad_field = client.patch(
        f"/api/projects/{pid}/findings/{f.finding_id}",
        json={"expected_revision": 1, "severity": "critical"},
    )
    assert bad_field.status_code == 422  # StrictModel rejects the unknown field outright

    stale = client.patch(
        f"/api/projects/{pid}/findings/{f.finding_id}",
        json={"expected_revision": 99, "analyst_status": "confirmed"},
    )
    assert stale.status_code == 409


def test_merge_and_unmerge_via_api(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    original = repo.create_finding(make_finding(pid, title="Original"))
    dup = repo.create_finding(make_finding(pid, title="Duplicate"))

    merge_resp = client.post(
        f"/api/projects/{pid}/findings/{dup.finding_id}/merge",
        json={"into_finding_id": original.finding_id, "expected_revision": 1, "note": "dup"},
    )
    assert merge_resp.status_code == 200
    assert merge_resp.json()["finding"]["merged_into"] == original.finding_id

    listed = client.get("/api/findings", params={"project_id": pid}).json()
    assert listed["total"] == 1  # the duplicate is hidden by default

    unmerge_resp = client.post(
        f"/api/projects/{pid}/findings/{dup.finding_id}/unmerge",
        json={"expected_revision": merge_resp.json()["finding"]["revision"]},
    )
    assert unmerge_resp.status_code == 200
    assert unmerge_resp.json()["finding"]["merged_into"] is None

    listed_again = client.get("/api/findings", params={"project_id": pid}).json()
    assert listed_again["total"] == 2


def test_merge_into_unknown_finding_is_404(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    resp = client.post(
        f"/api/projects/{pid}/findings/{f.finding_id}/merge",
        json={"into_finding_id": "fnd_" + "0" * 32, "expected_revision": 1},
    )
    assert resp.status_code == 404


def test_unknown_finding_routes_are_404(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    missing = "fnd_" + "0" * 32
    assert client.get(f"/api/projects/{pid}/findings/{missing}").status_code == 404
    assert (
        client.patch(
            f"/api/projects/{pid}/findings/{missing}",
            json={"expected_revision": 1, "analyst_status": "confirmed"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/projects/{pid}/findings/{missing}/comments",
            json={"text": "note", "expected_revision": 1},
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/projects/{pid}/findings/{missing}/unmerge",
            json={"expected_revision": 1},
        ).status_code
        == 404
    )


def test_comment_and_unmerge_reject_a_stale_revision(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    stale = client.post(
        f"/api/projects/{pid}/findings/{f.finding_id}/comments",
        json={"text": "note", "expected_revision": 99},
    )
    assert stale.status_code == 409

    other = repo.create_finding(make_finding(pid, title="other"))
    merge_resp = client.post(
        f"/api/projects/{pid}/findings/{f.finding_id}/merge",
        json={"into_finding_id": other.finding_id, "expected_revision": 1},
    )
    assert merge_resp.status_code == 200
    unmerge_stale = client.post(
        f"/api/projects/{pid}/findings/{f.finding_id}/unmerge",
        json={"expected_revision": 99},
    )
    assert unmerge_stale.status_code == 409
    # not merged at all -> unmerge is a conflict, not a 404 or a silent no-op
    not_merged = client.post(
        f"/api/projects/{pid}/findings/{other.finding_id}/unmerge",
        json={"expected_revision": other.revision},
    )
    assert not_merged.status_code == 409


def test_standards_catalogs_and_risk_formula_are_exposed(client: TestClient) -> None:
    catalogs = client.get("/api/standards/catalogs").json()
    by_name = {c["catalog"]: c for c in catalogs}
    assert by_name["owasp_top10"]["version"] == "2025"
    assert by_name["owasp_api_top10"]["version"] == "2023"
    assert by_name["cwe"]["entry_count"] > 0

    formula = client.get("/api/risk-formula").json()
    assert formula["severity_points"]["critical"] == 100.0
    assert formula["needs_review_tier_ceiling"] == "high"


def test_dashboard_findings_count_reconciles_with_filtered_list(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, severity="high"))
    repo.create_finding(make_finding(pid, severity="high"))
    repo.create_finding(make_finding(pid, severity="low"))
    summary = client.get("/api/dashboard/summary", params={"project_id": pid}).json()
    assert summary["findings"]["total"] == 3
    assert summary["findings"]["by_severity"]["high"] == 2
    high_list = client.get("/api/findings", params={"project_id": pid, "severity": "high"}).json()
    assert high_list["total"] == summary["findings"]["by_severity"]["high"]
    assert summary["trend"] == []  # no comparable completed scans exist yet


def test_dashboard_counts_exclude_merged_duplicates_like_the_default_findings_list(
    client: TestClient, repo: StorageRepository
) -> None:
    """A manually-merged duplicate is kept on disk (provenance/rollback) but is no longer a
    distinct open issue. The dashboard's unique-finding counts must reconcile with what the
    default (unfiltered, merged-excluded) findings list actually shows — the Phase 09
    acceptance criterion "Dashboard counts reconcile to filtered canonical finding records."
    """
    pid = _project(repo)
    original = repo.create_finding(make_finding(pid, title="Original", severity="high"))
    dup = repo.create_finding(make_finding(pid, title="Duplicate", severity="high"))
    repo.create_finding(make_finding(pid, title="Unrelated", severity="low"))

    before = client.get("/api/dashboard/summary", params={"project_id": pid}).json()
    assert before["findings"]["total"] == 3
    assert before["findings"]["by_severity"]["high"] == 2

    merge_resp = client.post(
        f"/api/projects/{pid}/findings/{dup.finding_id}/merge",
        json={"into_finding_id": original.finding_id, "expected_revision": 1},
    )
    assert merge_resp.status_code == 200

    after = client.get("/api/dashboard/summary", params={"project_id": pid}).json()
    findings_list = client.get("/api/findings", params={"project_id": pid}).json()
    high_list = client.get("/api/findings", params={"project_id": pid, "severity": "high"}).json()

    # the merged duplicate vanishes from every dashboard count exactly as it does from the
    # default findings list — both now agree on "2 unique findings, 1 of them high"
    assert after["findings"]["total"] == 2 == findings_list["total"]
    assert after["findings"]["by_severity"]["high"] == 1 == high_list["total"]
    # but the duplicate's own record, and its provenance, still exist on request
    assert repo.get_finding(pid, dup.finding_id).title == "Duplicate"
    with_merged = client.get(
        "/api/findings", params={"project_id": pid, "include_merged": True}
    ).json()
    assert with_merged["total"] == 3


def test_dashboard_trend_appears_only_with_comparable_completed_scans(
    client: TestClient, repo: StorageRepository
) -> None:
    from app.models.common import ScanModule, ScanState
    from app.models.scan import ScanJob

    pid = _project(repo)
    s1 = repo.create_scan(
        ScanJob(
            scan_id=new_id("scan"),
            project_id=pid,
            module=ScanModule.WEB_APP,
            state=ScanState.COMPLETED,
        )
    )
    repo.create_finding(make_finding(pid, scan_id=s1.scan_id, severity="high"))
    # Only one completed scan so far: no comparable pair, so no trend yet.
    summary_one = client.get("/api/dashboard/summary", params={"project_id": pid}).json()
    assert summary_one["trend"] == []

    s2 = repo.create_scan(
        ScanJob(
            scan_id=new_id("scan"),
            project_id=pid,
            module=ScanModule.WEB_APP,
            state=ScanState.COMPLETED,
        )
    )
    repo.create_finding(make_finding(pid, scan_id=s2.scan_id, severity="high"))
    repo.create_finding(make_finding(pid, scan_id=s2.scan_id, severity="critical"))

    summary_two = client.get("/api/dashboard/summary", params={"project_id": pid}).json()
    assert len(summary_two["trend"]) == 1
    t = summary_two["trend"][0]
    assert t["module"] == "web_app"
    assert t["newer_scan_id"] == s2.scan_id and t["older_scan_id"] == s1.scan_id
    assert t["findings_delta"] == 1
    assert t["by_severity_delta"]["critical"] == 1
