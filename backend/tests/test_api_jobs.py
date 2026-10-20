"""Phase 04 API: start/cancel/retry, detail/events/console, modules, status, kill switch."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.jobs.selftest import SelfTestRunner
from app.main import create_app
from app.models.common import ScanModule
from app.storage.repository import StorageRepository
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT
from tests.jobhelpers import LoopRunner, attested_project


@pytest.fixture
def jobs_client(settings: RuntimeSettings, repo: StorageRepository) -> Iterator[TestClient]:
    repo.settings = settings.model_copy(update={"enable_selftest_jobs": True})
    app = create_app(
        repo.settings, repository=repo, job_runners={ScanModule.SELF_TEST: SelfTestRunner()}
    )
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as c:
        yield c


def _start(c: TestClient, pid: str, **kw: Any) -> Any:
    body = {
        "module": "self_test",
        "targets": ["https://app.example.com/"],
        "confirmed": True,
        "parameters": {"steps": 3, "step_seconds": 0.05},
        **kw,
    }
    return c.post(
        f"/api/projects/{pid}/scans", json=body, headers={"X-Request-ID": "corr-api-000001"}
    )


def _wait(c: TestClient, pid: str, sid: str, timeout: float = 20) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = c.get(f"/api/projects/{pid}/scans/{sid}").json()
        if body["terminal"]:
            return body  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_start_run_and_inspect(jobs_client: TestClient, repo: StorageRepository) -> None:
    pid = attested_project(repo).project_id
    resp = _start(jobs_client, pid)
    assert resp.status_code == 202, resp.text
    scan = resp.json()
    assert scan["state"] == "queued" and scan["correlation_id"] == "corr-api-000001"
    detail = _wait(jobs_client, pid, scan["scan_id"])
    assert detail["scan"]["state"] == "completed" and detail["elapsed_seconds"] is not None
    assert detail["scan"]["progress"]["counters"]["steps_done"] == 3
    events = jobs_client.get(
        f"/api/projects/{pid}/scans/{scan['scan_id']}/events", params={"limit": 500}
    ).json()
    assert events["items"][0]["type"] == "state" and events["corrupt_lines"] == 0
    assert all(e["correlation_id"] == "corr-api-000001" for e in events["items"])
    console = jobs_client.get(f"/api/projects/{pid}/scans/{scan['scan_id']}/console").json()[
        "lines"
    ]
    assert any("stage: simulate" in line for line in console)
    listed = jobs_client.get("/api/scans", params={"project_id": pid}).json()
    assert listed["total"] == 1


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({"confirmed": False}, 422, "validation_failed"),
        ({"module": "web_app"}, 409, "module_unavailable"),
        ({"targets": ["https://evil.test/"]}, 422, "validation_failed"),
        ({"targets": []}, 422, "validation_failed"),
        ({"targets": ["https://app.example.com/"] * 51}, 422, "validation_failed"),
        ({"parameters": {"x" * 300: 1}}, 422, "validation_failed"),
        ({"parameters": {"Bad-Key": 1}}, 422, "validation_failed"),
        ({"parameters": {"steps": 1}}, 202, None),
    ],
)
def test_start_validation(
    jobs_client: TestClient,
    repo: StorageRepository,
    body: dict[str, Any],
    status: int,
    code: str | None,
) -> None:
    pid = attested_project(repo).project_id
    resp = _start(jobs_client, pid, **body)
    assert resp.status_code == status, resp.text
    if code:
        assert resp.json()["error"]["code"] == code


def test_start_requires_active_authorization(
    jobs_client: TestClient, repo: StorageRepository
) -> None:
    pid = attested_project(repo).project_id
    repo.update_project(pid, {"authorization": None})
    resp = _start(jobs_client, pid)
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "authorization_missing"
    assert jobs_client.get("/api/scans", params={"project_id": pid}).json()["total"] == 0


def test_idempotent_start_returns_existing_job(
    jobs_client: TestClient, repo: StorageRepository
) -> None:
    pid = attested_project(repo).project_id
    first = _start(jobs_client, pid, idempotency_key="double-click-0001")
    second = _start(jobs_client, pid, idempotency_key="double-click-0001")
    assert first.status_code == 202 and second.status_code == 200
    assert first.json()["scan_id"] == second.json()["scan_id"]


def test_cancel_and_retry(settings: RuntimeSettings, repo: StorageRepository) -> None:
    repo.settings = settings.model_copy(update={"enable_selftest_jobs": True})
    runner = LoopRunner()
    app = create_app(repo.settings, repository=repo, job_runners={ScanModule.SELF_TEST: runner})
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as c:
        pid = attested_project(repo).project_id
        sid = _start(c, pid).json()["scan_id"]
        assert runner.started.wait(10)
        cancel = c.post(f"/api/projects/{pid}/scans/{sid}/cancel")
        assert cancel.status_code == 202
        detail = _wait(c, pid, sid)
        assert (
            detail["scan"]["state"] == "cancelled"
            and "work/partial.txt" in detail["scan"]["output_refs"]
        )
        again = c.post(f"/api/projects/{pid}/scans/{sid}/cancel")
        assert again.status_code == 409
        runner.steps = 2
        retry = c.post(f"/api/projects/{pid}/scans/{sid}/retry", json={"confirmed": True})
        assert (
            retry.status_code == 202
            and retry.json()["retry_of"] == sid
            and retry.json()["scan_id"] != sid
        )
        assert _wait(c, pid, retry.json()["scan_id"])["scan"]["state"] == "completed"
        no_confirm = c.post(f"/api/projects/{pid}/scans/{sid}/retry", json={"confirmed": False})
        assert no_confirm.status_code == 422


def test_modules_status_and_kill_switch(jobs_client: TestClient, repo: StorageRepository) -> None:
    modules = {m["module"]: m for m in jobs_client.get("/api/jobs/modules").json()}
    assert modules["self_test"]["available"] is True
    assert modules["web_app"]["available"] is False and "Phase 05" in modules["web_app"]["reason"]
    status = jobs_client.get("/api/jobs/status").json()
    assert (
        status["running"] is True
        and status["max_active_jobs"] == 1
        and status["kill_switch_engaged"] is False
    )
    on = jobs_client.put("/api/kill-switch", json={"engaged": True, "reason": "incident 42"})
    assert on.status_code == 200 and on.json()["engaged"] is True
    pid = attested_project(repo).project_id
    blocked = _start(jobs_client, pid)
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "kill_switch_engaged"
    assert jobs_client.get("/api/kill-switch").json()["reason"] == "incident 42"
    assert (
        jobs_client.put("/api/kill-switch", json={"engaged": False, "reason": "resolved"}).json()[
            "engaged"
        ]
        is False
    )
    assert _start(jobs_client, pid).status_code == 202


def test_job_routes_reject_bad_ids(jobs_client: TestClient, repo: StorageRepository) -> None:
    pid = attested_project(repo).project_id
    for path in (
        f"/api/projects/{pid}/scans/../x",
        f"/api/projects/{pid}/scans/scn_123/events",
        f"/api/projects/{pid}/scans/scn_123/console",
    ):
        assert jobs_client.get(path).status_code in (400, 404)
    assert jobs_client.post(f"/api/projects/{pid}/scans/scn_123/cancel").status_code in (400, 404)
    assert jobs_client.get(f"/api/projects/{pid}/scans/scn_{'0' * 32}").status_code == 404
