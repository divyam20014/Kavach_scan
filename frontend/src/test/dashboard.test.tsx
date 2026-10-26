// UI/UX modernization, increment 3 (TBD-104): dashboard. No dashboard test existed before
// this file -- covers the empty state, KPIs sourced from real API data (never fabricated),
// the new "Critical & High findings" KPI, and the new "Recent scans" widget.
import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DashboardSummary, ScanJob } from "../api/types";
import { emptyPage, emptySummary, mockApi, PID, renderAt, VERSION } from "./utils";

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

function summary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    ...emptySummary(),
    projects: { total: 3, active: 2, archived: 1, authorization: { missing: 0, not_started: 0, active: 3, expiring_soon: 0, expired: 0 } },
    scans: { ...emptySummary().scans, total: 10, active: 1, failed: 2, last_scan_at: "2026-10-26T10:00:00Z", last_scan_state: "completed" },
    findings: {
      total: 8,
      open: 5,
      by_severity: { critical: 1, high: 2, medium: 3, low: 1, informational: 1 },
      by_status: { ...emptySummary().findings.by_status, retest_needed: 1 },
      by_confidence: { ...emptySummary().findings.by_confidence, confirmed: 4 },
    },
    assets: { total: 12, by_type: emptySummary().assets.by_type },
    ...overrides,
  };
}

function scan(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    scan_id: "scn_" + "1".repeat(32),
    project_id: PID,
    module: "web_app",
    profile: "default",
    state: "completed",
    revision: 1,
    created_at: "2026-10-26T09:00:00Z",
    updated_at: "2026-10-26T10:00:00Z",
    queued_at: "2026-10-26T09:00:00Z",
    started_at: "2026-10-26T09:01:00Z",
    finished_at: "2026-10-26T10:00:00Z",
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

describe("Dashboard", () => {
  it("shows the empty state with a guided next step when there is no data", async () => {
    mockApi({
      ...base,
      "GET /api/dashboard/summary": { body: emptySummary() },
      "GET /api/scans": { body: emptyPage() },
    });
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "No projects yet" })).toBeInTheDocument();
    for (const id of ["kpi-projects", "kpi-scans", "kpi-critical-high", "kpi-findings", "kpi-assets"]) {
      expect(screen.getByTestId(id).textContent).toMatch(/0/);
    }
    expect(await screen.findByText("No scans have been run yet.", { exact: false })).toBeInTheDocument();
  });

  it("renders real KPI values from the API, including Critical & High findings, never fabricated", async () => {
    mockApi({
      ...base,
      "GET /api/dashboard/summary": { body: summary() },
      "GET /api/scans": { body: emptyPage() },
    });
    renderAt("/");
    expect(await screen.findByTestId("kpi-projects")).toHaveTextContent("3");
    expect(screen.getByTestId("kpi-scans")).toHaveTextContent("10");
    expect(screen.getByTestId("kpi-failed-scans")).toHaveTextContent("2");
    // critical (1) + high (2) = 3, computed from the same by_severity data already shown
    // in the severity table below -- never a separate, independently-fabricated number.
    const criticalHigh = screen.getByTestId("kpi-critical-high");
    expect(criticalHigh).toHaveTextContent("3");
    expect(criticalHigh.closest("a")).toHaveAttribute("href", "/findings?severity=critical&severity=high");
  });

  it("shows the 5 most recent scans with links to the scan and its project", async () => {
    mockApi({
      ...base,
      "GET /api/dashboard/summary": { body: summary() },
      "GET /api/scans": { body: { ...emptyPage(), items: [scan()], total: 1 } },
    });
    renderAt("/");
    const card = await screen.findByRole("region", { name: "Recent scans" });
    expect(await within(card).findByText("Web app")).toBeInTheDocument();
    const scanLink = within(card).getByRole("link", { name: /scn_1{8}/ });
    expect(scanLink).toHaveAttribute("href", `/projects/${PID}/scans/scn_${"1".repeat(32)}`);
    expect(within(card).getByRole("link", { name: "All scans" })).toHaveAttribute("href", "/scans");
  });

  it("offers a 'New project' quick action in the header on every visit, not only when empty", async () => {
    mockApi({
      ...base,
      "GET /api/dashboard/summary": { body: summary() },
      "GET /api/scans": { body: emptyPage() },
    });
    renderAt("/");
    const link = await screen.findByRole("link", { name: "New project" });
    expect(link).toHaveAttribute("href", "/projects/new");
  });
});
