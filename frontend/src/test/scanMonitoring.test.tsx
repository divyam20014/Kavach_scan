// UI/UX modernization, increment 4 (TBD-105): scan monitoring. No test file existed for the
// global Scans list before this file. Covers the new Duration column and the "Last scan"
// link fix on the project detail page (scan_id was already in the API response but never
// used to link anywhere).
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Page, ScanJob } from "../api/types";
import { emptyPage, overview, PID, mockApi, renderAt, VERSION } from "./utils";

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

function scan(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    scan_id: "scn_" + "2".repeat(32),
    project_id: PID,
    module: "web_app",
    profile: "default",
    state: "completed",
    revision: 1,
    created_at: "2026-10-26T09:00:00Z",
    updated_at: "2026-10-26T09:05:30Z",
    queued_at: "2026-10-26T09:00:00Z",
    started_at: "2026-10-26T09:00:30Z",
    finished_at: "2026-10-26T09:05:30Z",
    targets: ["https://app.example.com"],
    authorized_targets: [],
    parameters: {},
    progress: { stage: "", percent: null, counters: {} },
    cancel_requested: false,
    warnings: [],
    errors: [],
    output_refs: [],
    correlation_id: null,
    retry_of: null,
    final_reason: "",
    scope_hash: null,
    ...overrides,
  };
}

describe("Scans list", () => {
  it("shows a Duration column computed from started/finished timestamps", async () => {
    mockApi({
      ...base,
      "GET /api/scans": { body: { ...emptyPage(), items: [scan()], total: 1 } as Page<ScanJob> },
    });
    renderAt("/scans");
    const row = await screen.findByRole("row", { name: /Web app/ });
    // 09:00:30 -> 09:05:30 = exactly 5 minutes
    expect(within(row).getByText("5m 0s")).toBeInTheDocument();
  });

  it("shows 'running…' for a scan that started but has not finished", async () => {
    mockApi({
      ...base,
      "GET /api/scans": { body: { ...emptyPage(), items: [scan({ finished_at: null, state: "running" })], total: 1 } as Page<ScanJob> },
    });
    renderAt("/scans");
    const row = await screen.findByRole("row", { name: /Web app/ });
    expect(within(row).getByText("running…")).toBeInTheDocument();
  });
});

describe("Project detail: last scan", () => {
  it("links the last-scan summary to its own scan detail page", async () => {
    const withLastScan = overview({}, { last_scan: { scan_id: "scn_" + "3".repeat(32), state: "completed", at: "2026-10-26T09:05:30Z" } });
    mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: withLastScan },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [] },
      [`GET /api/projects/${PID}/scope/policy`]: {
        body: {
          project_id: PID, scope: overview().project.scope, scope_hash: "a".repeat(64), valid: true,
          authorization: { decision_id: "d", at: "", allowed: true, reason: "allowed", message: "Authorization is active", check: "authorization", input: "", target: null, ip: null, rule: null, project_id: PID, scope_hash: null },
          can_start_active_work: true, internal_override: null, warnings: [], blocked_ranges: [],
        },
      },
    });
    renderAt(`/projects/${PID}`);
    const link = await screen.findByRole("link", { name: /Completed/ });
    expect(link).toHaveAttribute("href", `/projects/${PID}/scans/scn_${"3".repeat(32)}`);
  });

  it("offers a link to this project's full scan history", async () => {
    mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [] },
      [`GET /api/projects/${PID}/scope/policy`]: {
        body: {
          project_id: PID, scope: overview().project.scope, scope_hash: "a".repeat(64), valid: true,
          authorization: { decision_id: "d", at: "", allowed: true, reason: "allowed", message: "Authorization is active", check: "authorization", input: "", target: null, ip: null, rule: null, project_id: PID, scope_hash: null },
          can_start_active_work: true, internal_override: null, warnings: [], blocked_ranges: [],
        },
      },
    });
    renderAt(`/projects/${PID}`);
    const link = await screen.findByRole("link", { name: "View this project's scan history" });
    expect(link).toHaveAttribute("href", `/scans?project_id=${PID}`);
  });
});
