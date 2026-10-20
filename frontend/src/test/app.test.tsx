import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ApiError, request } from "../api/client";
import { emptyPage, emptySummary, mockApi, overview, PID, renderAt, VERSION } from "./utils";

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
};

describe("API client", () => {
  it("turns the backend error envelope into a typed ApiError with field messages", async () => {
    mockApi({
      "POST /api/projects": {
        status: 422,
        body: {
          error: {
            code: "validation_failed",
            message: "Request validation failed.",
            correlation_id: "abc-123",
            details: [{ loc: ["body", "authorization", "window_end"], message: "Value error, window_end must be after window_start", type: "value_error" }],
          },
        },
      },
    });
    const err = await request("POST", "/api/projects", { body: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const apiErr = err as ApiError;
    expect(apiErr.status).toBe(422);
    expect(apiErr.correlationId).toBe("abc-123");
    expect(apiErr.fieldErrors()["authorization.window_end"]).toMatch(/after window_start/);
    expect(apiErr.describe()).toMatch(/authorization › window_end/);
  });

  it("reports an unreachable backend clearly", async () => {
    globalThis.fetch = (() => Promise.reject(new TypeError("Failed to fetch"))) as typeof fetch;
    const err = (await request("GET", "/api/health").catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe("network_error");
    expect(err.message).toMatch(/python -m app/);
  });
});

describe("navigation and layout", () => {
  it("renders semantic navigation, honest unavailable modules and no scan controls", async () => {
    mockApi({ ...base, "GET /api/dashboard/summary": { body: emptySummary() } });
    renderAt("/");
    const nav = await screen.findByRole("navigation", { name: /main navigation/i });
    for (const label of ["Dashboard", "Projects", "Assets", "Scans", "Findings", "Audit log", "Settings & storage"]) {
      expect(within(nav).getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByRole("group", { name: /modules not available yet/i })).toHaveTextContent(/Reports/);
    expect(screen.queryByRole("button", { name: /start scan|run scan|scan now/i })).not.toBeInTheDocument();
    expect(screen.getByText(/scanners arrive in Phases 05–07/i)).toBeInTheDocument();
  });

  it("navigates between pages with a heading per page", async () => {
    mockApi({ ...base, "GET /api/dashboard/summary": { body: emptySummary() }, "GET /api/projects": { body: emptyPage() } });
    renderAt("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Dashboard" })).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("link", { name: "Projects" })[0]!);
    expect(await screen.findByRole("heading", { level: 1, name: "Projects" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: /breadcrumb/i })).toBeInTheDocument();
  });

  it("shows a not-found page for unknown routes", async () => {
    mockApi(base);
    renderAt("/no/such/page");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});

describe("dashboard", () => {
  it("shows honest zeros and an empty state when storage is empty", async () => {
    const { calls } = mockApi({ ...base, "GET /api/dashboard/summary": { body: emptySummary() } });
    renderAt("/");
    expect(await screen.findByTestId("kpi-projects")).toHaveTextContent("0");
    expect(screen.getByTestId("kpi-findings")).toHaveTextContent("0");
    expect(screen.getByRole("heading", { name: "No projects yet" })).toBeInTheDocument();
    expect(screen.getByText(/No findings recorded/)).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/api/dashboard/summary")).toBe(true);
  });

  it("renders counters from the API and links KPIs to pre-filtered views", async () => {
    const summary = emptySummary();
    summary.projects = { ...summary.projects, total: 3, active: 2, archived: 1 };
    summary.scans = { ...summary.scans, total: 7, active: 2, failed: 1 };
    summary.findings = { ...summary.findings, total: 5, open: 4, by_severity: { ...summary.findings.by_severity, high: 5 } };
    summary.findings.by_status.retest_needed = 2;
    summary.findings.by_confidence.confirmed = 3;
    summary.assets.total = 11;
    mockApi({ ...base, "GET /api/dashboard/summary": { body: summary } });
    renderAt("/");
    expect(await screen.findByTestId("kpi-projects")).toHaveTextContent("3");
    expect(screen.getByTestId("kpi-scans")).toHaveTextContent("7");
    expect(screen.getByTestId("kpi-assets")).toHaveTextContent("11");
    expect(screen.getByTestId("kpi-failed-scans")).toHaveAttribute("href", "/scans?state=failed");
    expect(screen.getByTestId("kpi-confirmed")).toHaveAttribute("href", "/findings?confidence=confirmed");
    expect(screen.getByTestId("kpi-retest")).toHaveAttribute("href", "/findings?analyst_status=retest_needed");
    expect(screen.getByRole("link", { name: "high findings" })).toHaveAttribute("href", "/findings?severity=high");
  });

  it("shows an error with retry when the backend fails", async () => {
    mockApi({ ...base, "GET /api/dashboard/summary": { status: 503, body: { error: { code: "service_unavailable", message: "Storage is not initialized", details: [] } } } });
    renderAt("/");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Storage is not initialized");
    expect(within(alert).getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("projects list and drill-down views", () => {
  it("shows an empty state with a create action", async () => {
    mockApi({ ...base, "GET /api/projects": { body: emptyPage() } });
    renderAt("/projects");
    expect(await screen.findByRole("heading", { name: "No projects yet" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Create your first project" })).toHaveAttribute("href", "/projects/new");
  });

  it("lists projects with text (not colour-only) authorization status", async () => {
    const expired = overview({ name: "Old engagement" }, { authorization_status: "expired" });
    mockApi({ ...base, "GET /api/projects": { body: { ...emptyPage(), items: [expired], total: 1 } } });
    renderAt("/projects");
    expect(await screen.findByRole("link", { name: "Old engagement" })).toHaveAttribute("href", `/projects/${PID}`);
    expect(screen.getByText("Authorization expired")).toBeInTheDocument();
    expect(screen.getByText("Never")).toBeInTheDocument();
  });

  it("passes URL filters to the findings API and explains empty results", async () => {
    const { calls } = mockApi({ ...base, "GET /api/findings": { body: emptyPage() } });
    renderAt("/findings?severity=high&confidence=confirmed");
    expect(await screen.findByRole("heading", { name: /No findings match/ })).toBeInTheDocument();
    const call = calls.find((c) => c.path === "/api/findings")!;
    expect(call.query.getAll("severity")).toEqual(["high"]);
    expect(call.query.getAll("confidence")).toEqual(["confirmed"]);
    expect(screen.getByRole("link", { name: "Clear filters" })).toHaveAttribute("href", "/findings");
  });

  it("states plainly that real scanners are not available yet", async () => {
    mockApi({ ...base, "GET /api/scans": { body: emptyPage() } });
    renderAt("/scans");
    expect(await screen.findByText(/real scanners arrive in Phases 05–07/)).toBeInTheDocument();
  });
});

describe("settings", () => {
  it("shows version, data-dir status and never marks unverified tools as available", async () => {
    mockApi({
      ...base,
      "GET /api/diagnostics/storage": {
        body: {
          storage: {
            data_dir: "~/AppData/Local/VAPTWorkbench/data",
            exists: true,
            initialized: true,
            writable: true,
            storage_version: 1,
            supported_storage_version: 1,
            instance_lock: "held_by_this_process",
            free_bytes: 10 * 1024 ** 3,
            total_bytes: 100 * 1024 ** 3,
            low_disk_space: false,
            warnings: [],
            ready: true,
            checked_at: "2026-10-20T00:00:00Z",
          },
          last_integrity_check: null,
        },
      },
    });
    renderAt("/settings");
    expect(await screen.findByText("~/AppData/Local/VAPTWorkbench/data")).toBeInTheDocument();
    expect(screen.getByText("✓ Ready")).toBeInTheDocument();
    expect(await screen.findByText("Not available in this build")).toBeInTheDocument();
    expect(screen.getByText(/none is reported as available/)).toBeInTheDocument();
  });
});

describe("project detail and deletion", () => {
  it("requires typing the exact name and shows impact before deleting", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview({}, { counts: { scan: 0, finding: 2, asset: 1, evidence: 0, import: 0, report: 0 } }) },
      [`GET /api/projects/${PID}/deletion-impact`]: { body: { project_id: PID, name: "Web assessment", counts: { finding: 2, asset: 1 }, confirm_with: "Web assessment" } },
      [`DELETE /api/projects/${PID}`]: { body: { project_id: PID, name: "Web assessment", counts: {}, confirm_with: "Web assessment" } },
      "GET /api/projects": { body: emptyPage() },
    });
    renderAt(`/projects/${PID}`);
    await userEvent.click(await screen.findByRole("button", { name: "Delete…" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("2 Finding record(s)")).toBeInTheDocument();
    const del = within(dialog).getByRole("button", { name: "Delete project" });
    expect(del).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox"), "web assessment");
    expect(del).toBeDisabled();
    await userEvent.clear(within(dialog).getByRole("textbox"));
    await userEvent.type(within(dialog).getByRole("textbox"), "Web assessment");
    expect(del).toBeEnabled();
    await userEvent.click(del);
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    expect(calls.find((c) => c.method === "DELETE")!.query.get("confirm")).toBe("Web assessment");
    // After deletion the user lands on the projects list, not on a 404 error screen.
    expect(await screen.findByRole("heading", { level: 1, name: "Projects" })).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "GET" && c.path === `/api/projects/${PID}`)).toHaveLength(1);
  });
});
