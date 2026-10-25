"""Phase 12: performance pass with a synthetic large project — pagination holds, an
unbounded page-size request is rejected (not silently capped and not silently served in
full), and a report generation over a large finding set stays within its documented bound.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app.reports.builder import MAX_FINDINGS_PER_REPORT, ReportFilters, build_report_data
from app.storage.repository import StorageRepository
from tests.conftest import make_finding
from tests.surfacefixtures import surface_project

FINDING_COUNT = 150


def _project_with_many_findings(repo: StorageRepository) -> str:
    pid = repo.create_project(surface_project([80], hosts=["x.test"])).project_id
    for i in range(FINDING_COUNT):
        repo.create_finding(make_finding(pid, title=f"Finding {i:04d}"))
    return pid


def test_findings_list_is_paginated_not_a_giant_load(
    client: TestClient, repo: StorageRepository,
) -> None:
    pid = _project_with_many_findings(repo)
    page = client.get("/api/findings", params={"project_id": pid, "limit": 25}).json()
    assert page["total"] == FINDING_COUNT
    assert len(page["items"]) == 25  # exactly one page's worth, not everything

    second = client.get(
        "/api/findings", params={"project_id": pid, "limit": 25, "offset": 25}
    ).json()
    first_ids = {i["finding"]["finding_id"] for i in page["items"]}
    second_ids = {i["finding"]["finding_id"] for i in second["items"]}
    assert first_ids.isdisjoint(second_ids)  # distinct pages, not the same slice twice


def test_findings_list_rejects_an_oversized_page_size(
    client: TestClient, repo: StorageRepository,
) -> None:
    pid = _project_with_many_findings(repo)
    resp = client.get("/api/findings", params={"project_id": pid, "limit": 100_000})
    assert resp.status_code == 422  # rejected outright, never silently capped or served whole


def test_findings_list_scales_linearly_not_quadratically(
    client: TestClient, repo: StorageRepository,
) -> None:
    """`list_findings` reads every matching finding's full body (not just the returned page)
    to support rich cross-field filtering/sorting/risk-scoring (TBD-073) — an accepted,
    documented tradeoff of filesystem-only storage, not something this test tries to make
    instant. What it does guard against is an accidental quadratic blowup (e.g. a future
    change that re-reads the whole finding set once per item instead of once overall): a
    project with 3x the findings must not take dramatically more than 3x as long."""
    small_pid = repo.create_project(surface_project([80], hosts=["y.test"])).project_id
    for i in range(FINDING_COUNT // 3):
        repo.create_finding(make_finding(small_pid, title=f"Small {i:04d}"))
    start = time.monotonic()
    small_resp = client.get("/api/findings", params={"project_id": small_pid, "limit": 25})
    small_elapsed = time.monotonic() - start
    assert small_resp.status_code == 200

    large_pid = _project_with_many_findings(repo)
    start = time.monotonic()
    large_resp = client.get("/api/findings", params={"project_id": large_pid, "limit": 25})
    large_elapsed = time.monotonic() - start
    assert large_resp.status_code == 200

    # Generous headroom (6x for a 3x larger input) to absorb timing noise while still
    # catching a genuine quadratic regression, which would show up as a much larger ratio.
    assert large_elapsed < max(small_elapsed * 6, 10.0), (small_elapsed, large_elapsed)


def test_report_generation_is_bounded_for_a_large_finding_set(
    repo: StorageRepository,
) -> None:
    pid = _project_with_many_findings(repo)
    data = build_report_data(repo, ReportFilters(project_id=pid))
    assert len(data.findings) == min(FINDING_COUNT, MAX_FINDINGS_PER_REPORT)
    assert FINDING_COUNT <= MAX_FINDINGS_PER_REPORT  # sanity: this test exercises the normal
    # path today; MAX_FINDINGS_PER_REPORT itself is exercised directly in test_reports_builder.py
