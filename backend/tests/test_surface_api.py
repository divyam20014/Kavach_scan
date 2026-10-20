"""Phase 06 API: surface scan profile preview, asset graph/ranking, criticality, approval."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models.asset import Asset
from app.models.common import AssetType, Confidence, ScopeStatus, Severity, new_id
from app.models.finding import Finding
from app.storage.repository import StorageRepository
from tests.surfacefixtures import surface_project

PID_HOSTS = ["lab.test", "www.lab.test"]


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80, 443], hosts=PID_HOSTS)).project_id


def test_surface_profile_preview(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    resp = client.get(
        f"/api/projects/{pid}/surface-scan-profile",
        params={"targets": ["lab.test"], "ports": "80,443,9999", "passive_crtsh": "true"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["problems"] == [] and body["target_problems"] == []
    assert body["profile"]["ports"]["tested"] == [80, 443]
    assert "9999" in body["profile"]["ports"]["not_tested"]
    crtsh = next(s for s in body["profile"]["sources"] if s["name"] == "crtsh")
    assert crtsh["enabled"] is True and "third-party" in crtsh["disclosure"]
    assert any("not built" not in lim.lower() for lim in body["profile"]["limitations"])


def test_surface_profile_rejects_bad_target_and_params(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    resp = client.get(
        f"/api/projects/{pid}/surface-scan-profile",
        params={"targets": ["nope.example"], "ports": "1-5"},
    ).json()
    assert resp["target_problems"] and any("neither" in t for t in resp["target_problems"])
    assert resp["problems"]  # port range rejected


def _asset(
    repo: StorageRepository, pid: str, atype: AssetType, locator: str, **kw: object
) -> Asset:
    return repo.create_asset(
        Asset(asset_id=new_id("asset"), project_id=pid, asset_type=atype, locator=locator, **kw)
    )  # type: ignore[arg-type]


def test_surface_view_graph_ranking_and_filters(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    host = _asset(repo, pid, AssetType.HOSTNAME, "lab.test", scope_status=ScopeStatus.IN_SCOPE)
    ip = _asset(
        repo,
        pid,
        AssetType.IP,
        "127.0.0.1",
        parent_asset_id=host.asset_id,
        scope_status=ScopeStatus.IN_SCOPE,
    )
    port = _asset(
        repo,
        pid,
        AssetType.PORT,
        "tcp://127.0.0.1:3306",
        parent_asset_id=ip.asset_id,
        scope_status=ScopeStatus.IN_SCOPE,
        attributes={"port": 3306},
    )
    _asset(repo, pid, AssetType.HOSTNAME, "new.lab.test", scope_status=ScopeStatus.PENDING_APPROVAL)
    repo.create_finding(
        Finding(
            finding_id=new_id("finding"),
            project_id=pid,
            title="DB reachable",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            affected_asset_ids=[port.asset_id],
        )
    )
    view = client.get(f"/api/projects/{pid}/surface").json()
    assert view["total"] == 4
    ranks = {r["asset"]["locator"]: r for r in view["items"]}
    assert ranks["lab.test"]["priority"] >= 30  # inherits medium finding + sensitive port
    assert ranks["new.lab.test"]["priority"] == 0  # discovered only
    assert (ip.asset_id, port.asset_id) in [tuple(e) for e in view["edges"]]
    assert view["counts"]["status"]["pending_approval"] == 1
    # filter by status
    only_pending = client.get(
        f"/api/projects/{pid}/surface", params={"status": "pending_approval"}
    ).json()
    assert (
        only_pending["total"] == 1
        and only_pending["items"][0]["asset"]["locator"] == "new.lab.test"
    )


def test_set_criticality_and_audit(client: TestClient, repo: StorageRepository) -> None:
    pid = _project(repo)
    host = _asset(repo, pid, AssetType.HOSTNAME, "lab.test", scope_status=ScopeStatus.IN_SCOPE)
    resp = client.patch(
        f"/api/projects/{pid}/assets/{host.asset_id}",
        json={"expected_revision": host.revision, "criticality": "high"},
    )
    assert resp.status_code == 200 and resp.json()["criticality"] == "high"
    view = client.get(f"/api/projects/{pid}/surface").json()
    assert view["items"][0]["priority"] == 20  # criticality alone, transparently
    audit = client.get("/api/audit", params={"project_id": pid}).json()
    assert any(e["action"] == "asset_criticality_changed" for e in audit["items"])


def test_approve_discovered_host_adds_to_scope_and_audits(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    project = repo.get_project(pid)
    # new.lab.test is a pending-approval subdomain of the in-scope lab.test
    pending = _asset(
        repo, pid, AssetType.HOSTNAME, "new.lab.test", scope_status=ScopeStatus.PENDING_APPROVAL
    )
    resp = client.post(
        f"/api/projects/{pid}/assets/{pending.asset_id}/approve",
        json={"expected_project_revision": project.revision, "confirmed": True},
    )
    assert resp.status_code == 200
    assert "new.lab.test" in resp.json()["scope"]["hosts"]
    assert repo.get_asset(pid, pending.asset_id).scope_status == ScopeStatus.IN_SCOPE
    audit = client.get("/api/audit", params={"project_id": pid}).json()
    actions = {e["action"] for e in audit["items"]}
    assert "asset_approved" in actions and "scope_changed" in actions


def test_approve_requires_confirmation_and_pending_status(
    client: TestClient, repo: StorageRepository
) -> None:
    pid = _project(repo)
    project = repo.get_project(pid)
    out = _asset(
        repo, pid, AssetType.HOSTNAME, "nope.example", scope_status=ScopeStatus.OUT_OF_SCOPE
    )
    unconfirmed = client.post(
        f"/api/projects/{pid}/assets/{out.asset_id}/approve",
        json={"expected_project_revision": project.revision, "confirmed": False},
    )
    assert unconfirmed.status_code == 422
    confirmed = client.post(
        f"/api/projects/{pid}/assets/{out.asset_id}/approve",
        json={"expected_project_revision": project.revision, "confirmed": True},
    )
    assert confirmed.status_code == 422  # out-of-scope host cannot be approved here
