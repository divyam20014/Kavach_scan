// Phase 04 UI: job detail (live progress, events, console, cancel), start-job confirmation, kill switch.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ScanDetail, ScanJob, ScopePolicyView } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "d".repeat(32);

function job(over: Partial<ScanJob> = {}): ScanJob {
  return {
    scan_id: SID, project_id: PID, module: "self_test", profile: "default", state: "running", revision: 3,
    created_at: "2026-11-01T10:00:00Z", updated_at: "2026-11-01T10:00:05Z", queued_at: "2026-11-01T10:00:00Z",
    started_at: "2026-11-01T10:00:01Z", finished_at: null, targets: ["https://app.example.com/"],
    authorized_targets: ["https://app.example.com/"], parameters: {},
    progress: { stage: "simulate", percent: 40, counters: { steps_done: 2, simulated_requests: 2 } },
    cancel_requested: false, warnings: ["self-test warning requested at step 2"], errors: [], output_refs: [],
    correlation_id: "corr-ui-1", retry_of: null, final_reason: "", scope_hash: "a".repeat(64), ...over,
  };
}

const detail = (scan: ScanJob, terminal = false): ScanDetail => ({ scan, active: !terminal, terminal, elapsed_seconds: 4.2 });

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
  [`GET /api/projects/${PID}/scans/${SID}/events`]: {
    body: { items: [{ event_id: "evt_1", ts: "2026-11-01T10:00:03Z", scan_id: SID, type: "stage", level: "info", stage: "simulate", message: "stage: simulate", data: {}, correlation_id: "corr-ui-1" }], offset: 0, limit: 200, has_more: false, corrupt_lines: 0 },
  },
  [`GET /api/projects/${PID}/scans/${SID}/console`]: { body: { lines: ["2026-11-01T10:00:03Z INFO    [simulate] stage: simulate"] } },
};

describe("job detail page", () => {
  it("shows live state, stage, progress, counters, warnings, events and console", async () => {
    mockApi({ ...base, [`GET /api/projects/${PID}/scans/${SID}`]: { body: detail(job()) } });
    renderAt(`/projects/${PID}/scans/${SID}`);
    expect(await screen.findByText(/Live: refreshing/)).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.getByLabelText("Progress 40%")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /Steps done 2/ })).toBeInTheDocument();
    expect(screen.getByText(/self-test warning requested/)).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Job events" })).toHaveTextContent("stage: simulate");
    expect(screen.getByLabelText("Console log output")).toHaveTextContent("[simulate] stage: simulate");
  });

  it("cancels only after confirmation", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: detail(job()) },
      [`POST /api/projects/${PID}/scans/${SID}/cancel`]: { status: 202, body: job({ cancel_requested: true }) },
    });
    renderAt(`/projects/${PID}/scans/${SID}`);
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Cancel job" }));
    const dialog = await screen.findByRole("dialog");
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await u.click(within(dialog).getByRole("button", { name: "Cancel job" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/cancel"))).toBe(true));
  });

  it("hides cancel for finished jobs and offers retry for unsuccessful ones", async () => {
    mockApi({ ...base, [`GET /api/projects/${PID}/scans/${SID}`]: {
      body: detail(job({ state: "interrupted", finished_at: "2026-11-01T10:01:00Z", final_reason: "The application stopped while this job was active. Partial results are kept; the job was NOT replayed automatically." }), true) } });
    renderAt(`/projects/${PID}/scans/${SID}`);
    expect(await screen.findByText(/NOT replayed automatically/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel job" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry as new job" })).toBeInTheDocument();
    expect(screen.queryByText(/Live: refreshing/)).not.toBeInTheDocument();
  });
});

function policy(open: boolean): ScopePolicyView {
  return {
    project_id: PID, scope: overview().project.scope, scope_hash: "a".repeat(64), valid: true,
    authorization: { decision_id: "d", at: "", allowed: open, reason: open ? "allowed" : "authorization_expired", message: open ? "Authorization is active" : "Authorization window ended", check: "authorization", input: "", target: null, ip: null, rule: null, project_id: PID, scope_hash: null },
    can_start_active_work: open, internal_override: null, warnings: [], blocked_ranges: [],
  };
}

function projectApi(open: boolean, extra: Record<string, unknown> = {}) {
  return mockApi({
    ...base,
    [`GET /api/projects/${PID}`]: { body: overview() },
    [`GET /api/projects/${PID}/scope/policy`]: { body: policy(open) },
    "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
    "GET /api/jobs/modules": { body: [
      { module: "web_app", label: "Web application scanner (Option A)", available: false, reason: "Scanner not implemented yet (Phase 05)" },
      { module: "self_test", label: "Job system self-test (no network traffic)", available: true, reason: "" },
    ] },
    ...(extra as Record<string, { body: unknown }>),
  });
}

describe("start a job", () => {
  it("shows unavailable modules disabled with the reason and requires confirmation", async () => {
    const { calls } = projectApi(true, { [`POST /api/projects/${PID}/scans`]: { status: 202, body: job({ state: "queued" }) },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: detail(job({ state: "queued" })) } });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    const web = await within(card).findByRole("radio", { name: /Web application scanner.*unavailable: Scanner not implemented yet \(Phase 05\)/ });
    expect(web).toBeDisabled();
    await u.click(within(card).getByRole("radio", { name: /self-test/ }));
    await u.type(within(card).getByRole("textbox", { name: /targets/i }), "https://app.example.com/");
    await u.click(within(card).getByRole("button", { name: /Review & confirm/ }));
    const dialog = await screen.findByRole("dialog");
    const startBtn = within(dialog).getByRole("button", { name: "Start job" });
    expect(startBtn).toBeDisabled();
    await u.click(within(dialog).getByRole("checkbox", { name: /I confirm/ }));
    await u.click(startBtn);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/scans"))).toBe(true));
    const body = calls.find((c) => c.method === "POST")!.body as { confirmed: boolean; idempotency_key: string; targets: string[] };
    expect(body.confirmed).toBe(true);
    expect(body.targets).toEqual(["https://app.example.com/"]);
    expect(body.idempotency_key).toMatch(/^ui-/);
  });

  it("disables starting when the safety gate is closed", async () => {
    projectApi(false);
    renderAt(`/projects/${PID}`);
    const card = await screen.findByRole("region", { name: "Start a job" });
    expect(await within(card).findByText(/Active work is blocked: Authorization window ended/)).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: /Review & confirm/ })).toBeDisabled();
  });
});

describe("kill switch", () => {
  it("engages only with a reason and shows the engaged state", async () => {
    const { calls } = mockApi({
      ...base,
      "GET /api/dashboard/summary": { body: (await import("./utils")).emptySummary() },
      "PUT /api/kill-switch": { body: { engaged: true, changed_at: "2026-11-01T10:00:00Z", reason: "incident", actor: "local-operator" } },
    });
    renderAt("/");
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Kill switch…" }));
    const dialog = await screen.findByRole("dialog");
    const engage = within(dialog).getByRole("button", { name: "Engage kill switch" });
    expect(engage).toBeDisabled();
    await u.type(within(dialog).getByRole("textbox", { name: /reason/i }), "incident");
    await u.click(engage);
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ engaged: true, reason: "incident" });
  });
});

describe("job completion refresh", () => {
  it("fetches events and console once more when the job becomes terminal", async () => {
    let terminalNow = false;
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}/scans/${SID}`]: () => ({ body: detail(job({ state: terminalNow ? "completed" : "running" }), terminalNow) }),
    });
    renderAt(`/projects/${PID}/scans/${SID}`);
    await screen.findByText(/Live: refreshing/);
    const before = calls.filter((c) => c.path.endsWith("/events")).length;
    terminalNow = true;
    await screen.findByText("Completed", {}, { timeout: 5000 });
    await waitFor(() => expect(calls.filter((c) => c.path.endsWith("/events")).length).toBeGreaterThan(before));
    await waitFor(() => expect(calls.filter((c) => c.path.endsWith("/console")).length).toBeGreaterThan(1));
  });
});
