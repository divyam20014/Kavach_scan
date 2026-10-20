"""Phase 03 API: scope policy view, dry-run checks, internal-target override, preview-hash gate."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.storage.repository import StorageRepository
from tests.test_api_projects import _auth, preview_hash

NOW = datetime.now(UTC)


def _project(client: TestClient, scope: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any]:
    scope = scope or {
        "hosts": ["app.example.com"],
        "ip_ranges": ["10.20.0.0/24"],
        "path_prefixes": ["/"],
    }
    body = {
        "name": "Scoped",
        "client_name": "C",
        "authorization": _auth(),
        "scope": scope,
        "scope_preview_hash": preview_hash(scope),
        **kw,
    }
    resp = client.post("/api/projects", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


def test_blocked_ranges_listing(client: TestClient) -> None:
    ranges = client.get("/api/scope/blocked-ranges").json()
    nets = {r["network"]: r for r in ranges}
    assert nets["169.254.169.254/32"]["overridable"] is False
    assert nets["10.0.0.0/8"]["overridable"] is True
    assert "127.0.0.0/8" in nets and "::1/128" in nets and "fc00::/7" in nets


def test_policy_view_shows_gate_warnings_and_override(client: TestClient) -> None:
    pid = _project(client)["project_id"]
    view = client.get(f"/api/projects/{pid}/scope/policy").json()
    assert view["valid"] and view["can_start_active_work"] is True
    assert view["authorization"]["reason"] == "allowed"
    assert any("10.20.0.0/24" in w and "override" in w for w in view["warnings"])
    assert view["internal_override"] is None and len(view["blocked_ranges"]) >= 25


@pytest.mark.parametrize(
    ("auth", "reason"),
    [
        (None, "authorization_missing"),
        (
            {
                "window_start": (NOW - timedelta(days=9)).isoformat(),
                "window_end": (NOW - timedelta(days=1)).isoformat(),
            },
            "authorization_expired",
        ),
        (
            {
                "window_start": (NOW + timedelta(days=1)).isoformat(),
                "window_end": (NOW + timedelta(days=9)).isoformat(),
            },
            "authorization_not_started",
        ),
    ],
)
def test_expired_or_absent_authorization_blocks_active_work(
    client: TestClient, auth: dict[str, Any] | None, reason: str
) -> None:
    pid = _project(client, authorization=None if auth is None else _auth(**auth))["project_id"]
    view = client.get(f"/api/projects/{pid}/scope/policy").json()
    assert view["can_start_active_work"] is False and view["authorization"]["reason"] == reason
    check = client.post(
        f"/api/projects/{pid}/scope/check", json={"url": "https://app.example.com/"}
    ).json()
    assert check["allowed"] is False and check["target"]["allowed"] is True
    assert check["authorization"]["reason"] == reason


@pytest.mark.parametrize(
    ("url", "ips", "allowed", "reason"),
    [
        ("https://app.example.com/x", [], True, "allowed"),
        ("https://app.example.com/x", ["93.184.216.34"], True, "allowed"),
        ("https://app.example.com/x", ["127.0.0.1"], False, "ip_blocked_range"),
        ("https://app.example.com/x", ["169.254.169.254"], False, "ip_cloud_metadata"),
        ("https://app.example.com.evil.test/", [], False, "host_out_of_scope"),
        ("https://10.20.0.5/", [], False, "ip_blocked_range"),
        ("https://user:pw@app.example.com/", [], False, "userinfo_in_url"),
        ("https://0x7f.1/", [], False, "ambiguous_host"),
    ],
)
def test_dry_run_check(
    client: TestClient, url: str, ips: list[str], allowed: bool, reason: str
) -> None:
    pid = _project(client)["project_id"]
    body = client.post(
        f"/api/projects/{pid}/scope/check", json={"url": url, "resolved_ips": ips}
    ).json()
    assert body["allowed"] is allowed, body
    reasons = [body["target"]["reason"], *[d["reason"] for d in body["resolved_ips"]]]
    assert reason in reasons
    if allowed and not ips:
        assert "DNS was not resolved" in body["dns_note"]


def test_classify_discovered_host(client: TestClient) -> None:
    pid = _project(
        client, scope={"hosts": ["app.example.com"], "wildcard_domains": ["*.svc.example.com"]}
    )["project_id"]

    def classify(host: str) -> str:
        resp = client.post(f"/api/projects/{pid}/scope/classify-host", json={"host": host})
        return str(resp.json()["status"])

    assert classify("x.svc.example.com") == "in_scope"
    assert classify("dev.app.example.com") == "pending_approval"
    assert classify("evil.test") == "out_of_scope"


# ------------------------------------------------------------------ internal-target override


def _override(client: TestClient, pid: str, revision: int, **kw: Any) -> Any:
    body = {
        "expected_revision": revision,
        "ip_ranges": ["10.20.0.0/24"],
        "reason": "internal staging network",
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
        "attestation": True,
        **kw,
    }
    return client.put(f"/api/projects/{pid}/internal-override", json=body)


def test_override_lifecycle_is_audited_and_unlocks_only_its_ranges(
    client: TestClient, repo: StorageRepository
) -> None:
    project = _project(client)
    pid = project["project_id"]
    resp = _override(client, pid, project["revision"])
    assert resp.status_code == 200, resp.text
    stored = resp.json()["scope"]["internal_override"]
    assert stored["audit_event_id"].startswith("evt_")
    check = client.post(
        f"/api/projects/{pid}/scope/check", json={"url": "https://10.20.0.5/"}
    ).json()
    assert check["allowed"] is True and "override" in check["target"]["rule"]
    still_blocked = client.post(
        f"/api/projects/{pid}/scope/check",
        json={"url": "https://app.example.com/", "resolved_ips": ["127.0.0.1"]},
    ).json()
    assert still_blocked["allowed"] is False
    view = client.get(f"/api/projects/{pid}/scope/policy").json()
    assert view["internal_override"]["active"] is True
    removed = client.delete(
        f"/api/projects/{pid}/internal-override",
        params={"expected_revision": resp.json()["revision"]},
    )
    assert removed.status_code == 200 and removed.json()["scope"]["internal_override"] is None
    actions = [e.action for e in repo.audit.list(project_id=pid).items]
    assert "internal_override_set" in actions and "internal_override_removed" in actions


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"attestation": False}, "attestation is required"),
        ({"ip_ranges": ["10.0.0.0/8"]}, "too broad"),
        ({"ip_ranges": ["169.254.0.0/16"]}, "cloud metadata"),
        ({"ip_ranges": ["93.184.216.0/24"]}, "not a blocked range"),
        ({"expires_at": (NOW - timedelta(minutes=1)).isoformat()}, "in the future"),
        ({"expires_at": (NOW + timedelta(days=91)).isoformat()}, "at most 90 days"),
        ({"reason": "short"}, "at least 10"),
    ],
)
def test_override_guardrails(client: TestClient, overrides: dict[str, Any], fragment: str) -> None:
    project = _project(client)
    resp = _override(client, project["project_id"], project["revision"], **overrides)
    assert resp.status_code == 422
    assert fragment.lower() in resp.text.lower()


def test_override_cannot_be_smuggled_through_project_create_or_update(client: TestClient) -> None:
    sneaky = {
        "hosts": ["app.example.com"],
        "internal_override": {
            "ip_ranges": ["127.0.0.0/8"],
            "reason": "sneaky override attempt",
            "audit_event_id": "evt_" + "0" * 32,
            "expires_at": (NOW + timedelta(days=1)).isoformat(),
        },
    }
    resp = client.post(
        "/api/projects",
        json={
            "name": "x",
            "client_name": "y",
            "scope": sneaky,
            "scope_preview_hash": preview_hash(sneaky),
        },
    )
    assert resp.status_code == 422 and "dedicated" in resp.text
    project = _project(client)
    patch = client.patch(
        f"/api/projects/{project['project_id']}",
        json={
            "expected_revision": project["revision"],
            "scope": sneaky,
            "scope_preview_hash": preview_hash(sneaky),
        },
    )
    assert patch.status_code == 422


def test_scope_edit_preserves_existing_override_and_needs_preview(client: TestClient) -> None:
    project = _project(client)
    pid = project["project_id"]
    rev = _override(client, pid, project["revision"]).json()["revision"]
    new_scope = {
        "hosts": ["app2.example.com"],
        "ip_ranges": ["10.20.0.0/24"],
        "path_prefixes": ["/"],
    }
    unpreviewed = client.patch(
        f"/api/projects/{pid}", json={"expected_revision": rev, "scope": new_scope}
    )
    assert unpreviewed.status_code == 422 and "previewed" in unpreviewed.text
    ok = client.patch(
        f"/api/projects/{pid}",
        json={
            "expected_revision": rev,
            "scope": new_scope,
            "scope_preview_hash": preview_hash(new_scope),
        },
    )
    assert ok.status_code == 200
    assert ok.json()["scope"]["hosts"] == ["app2.example.com"]
    assert ok.json()["scope"]["internal_override"] is not None  # kept; only its endpoint changes it


def test_preview_hash_round_trip_through_preview_endpoint(client: TestClient) -> None:
    preview = client.post("/api/scope/preview", json={"targets": ["shop.example.org"]}).json()
    resp = client.post(
        "/api/projects",
        json={
            "name": "P",
            "client_name": "C",
            "scope": preview["scope"],
            "scope_preview_hash": preview["scope_hash"],
        },
    )
    assert resp.status_code == 201
    tampered = dict(preview["scope"], hosts=["other.example.org"])
    resp = client.post(
        "/api/projects",
        json={
            "name": "P2",
            "client_name": "C",
            "scope": tampered,
            "scope_preview_hash": preview["scope_hash"],
        },
    )
    assert resp.status_code == 422


def test_scope_routes_reject_bad_ids(client: TestClient) -> None:
    for method, path in [
        ("GET", "/api/projects/../x/scope/policy"),
        ("POST", "/api/projects/prj_1/scope/check"),
    ]:
        resp = client.request(method, path, json={"url": "https://a.example.com/"})
        assert resp.status_code in (400, 404, 422)
