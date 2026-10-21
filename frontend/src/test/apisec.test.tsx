// Phase 07 UI: API spec inventory page, start-dialog options, API scan detail tabs.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ApiSpecDetail, ApiSpecSummary, ApiSummary, ScanDetail, ScanJob, ScopePolicyView } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "7".repeat(32);
const IMP = "imp_" + "a".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

function specSummary(): ApiSpecSummary {
  return { import_id: IMP, display_filename: "shop.json", sha256: "a".repeat(64), size_bytes: 1200,
    status: "parsed", uploaded_at: "2026-11-01T10:00:00Z", kind: "openapi3", version: "3.0.3",
    title: "Shop API", operation_count: 2, warnings: [] };
}

function specDetail(): ApiSpecDetail {
  return {
    summary: specSummary(),
    inventory: {
      kind: "openapi3", version: "3.0.3", title: "Shop API",
      servers: [{ raw: "https://api.shop.test/v1", expanded: "https://api.shop.test/v1" }],
      operations: [
        { op_id: "getOrder", method: "GET", path: "/orders/{id}", key: "GET /orders/{id}", summary: "", tags: ["orders"], deprecated: false, auth_schemes: ["bearerAuth"], security_required: true, parameters: [{ name: "id", location: "path", required: true, type: "string" }], request_content_types: [], request_schema_props: [], request_required_props: [], response_codes: ["200"], response_content_types: ["application/json"], mutating: false },
        { op_id: "createUser", method: "POST", path: "/users", key: "POST /users", summary: "", tags: [], deprecated: false, auth_schemes: [], security_required: false, parameters: [], request_content_types: ["application/json"], request_schema_props: ["name", "isAdmin"], request_required_props: ["name"], response_codes: ["201"], response_content_types: [], mutating: true },
      ],
      security_schemes: { bearerAuth: "http bearer" }, warnings: ["1 remote $ref(s) were NOT fetched"],
      remote_refs: ["https://x/y"], cyclic_refs: [], global_security: false, operation_count: 2,
    },
    servers: [{ raw: "https://api.shop.test/v1", expanded: "https://api.shop.test/v1", in_scope: true, reason: "allowed" }],
  };
}

describe("API spec inventory page", () => {
  it("lists specs and shows the operation inventory with mutability and scope-checked servers", async () => {
    mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/api-specs`]: { body: [specSummary()] },
      [`GET /api/projects/${PID}/api-specs/${IMP}`]: { body: specDetail() },
    });
    renderAt(`/projects/${PID}/api-specs`);
    const u = userEvent.setup();
    expect(await screen.findByText("shop.json")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Inventory" }));
    const table = await screen.findByRole("table", { name: "API operations" });
    expect(table).toHaveTextContent("/orders/{id}");
    expect(within(table).getByText("read-only")).toBeInTheDocument();
    expect(within(table).getByText("mutating")).toBeInTheDocument();
    expect(table).toHaveTextContent("isAdmin");
    expect(screen.getByText(/in scope/)).toBeInTheDocument();
    expect(screen.getByText(/remote \$ref/)).toBeInTheDocument();
  });
});

function policy(): ScopePolicyView {
  return {
    project_id: PID, scope: overview().project.scope, scope_hash: "a".repeat(64), valid: true,
    authorization: { decision_id: "d", at: "", allowed: true, reason: "allowed", message: "Authorization is active", check: "authorization", input: "", target: null, ip: null, rule: null, project_id: PID, scope_hash: null },
    can_start_active_work: true, internal_override: null, warnings: [], blocked_ranges: [],
  };
}

describe("API scan start dialog", () => {
  it("requires a spec, defaults to inventory-only, and sends inventory_only params", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [{ module: "api_security", label: "API security testing (Option C)", available: true, reason: "" }] },
      [`GET /api/projects/${PID}/api-specs`]: { body: [specSummary()] },
      [`GET /api/projects/${PID}/api-specs/${IMP}`]: { body: specDetail() },
      [`POST /api/projects/${PID}/api-security-plan`]: { body: { problems: [], inventory_only: true, server_in_scope: false, server_reason: "", operations_total: 2 } },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: { scan_id: SID, project_id: PID, module: "api_security", profile: "default", state: "queued", revision: 1, created_at: "", updated_at: "", queued_at: "", started_at: null, finished_at: null, targets: ["api-spec"], authorized_targets: [], parameters: {}, progress: { stage: "", percent: null, counters: {} }, cancel_requested: false, warnings: [], errors: [], output_refs: [], correlation_id: null, retry_of: null, final_reason: "", scope_hash: null } },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: { scan_id: SID, project_id: PID, module: "api_security", profile: "default", state: "queued", revision: 1, created_at: "", updated_at: "", queued_at: "", started_at: null, finished_at: null, targets: ["api-spec"], authorized_targets: [], parameters: {}, progress: { stage: "", percent: null, counters: {} }, cancel_requested: false, warnings: [], errors: [], output_refs: [], correlation_id: null, retry_of: null, final_reason: "", scope_hash: null }, active: false, terminal: false, elapsed_seconds: null } },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /API security testing/ }));
    // choose the spec
    await u.click(await within(card).findByRole("textbox", { name: "API specification" }));
    await u.click(await screen.findByText(/shop.json \(2 ops\)/));
    await u.click(within(card).getByRole("button", { name: /Review & confirm/ }));
    const dialog = await screen.findByRole("dialog");
    await u.click(within(dialog).getByRole("checkbox", { name: /I confirm/ }));
    await u.click(within(dialog).getByRole("button", { name: "Start job" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/scans"))).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path.endsWith("/scans"))!.body as { module: string; parameters: Record<string, unknown>; targets: string[] };
    expect(body.module).toBe("api_security");
    expect(body.parameters.inventory_only).toBe(true);
    expect(body.parameters.import_id).toBe(IMP);
  });
});

function apiSummary(): ApiSummary {
  return {
    schema_version: 1, catalog_version: "1.0.0", stopped_early: "", import_id: IMP, spec: "Shop API 2.1",
    spec_kind: "openapi3", spec_version: "3.0.3", server: "", inventory_only: true, operations_total: 2,
    operations_tested: [], operations_skipped: {}, requests_sent: 0, auth_aliases_used: [],
    idor_enabled: false, mass_write_enabled: false, rate_probe_enabled: false,
    check_outcomes: [{ outcome: "observation", count: 1 }, { outcome: "finding", count: 1 }, { outcome: "skipped", count: 13 }],
    findings_created: 1, findings_reobserved: 0, warnings: [], remote_refs: [],
    limitations: ["HTTP status alone is not proof of an access-control outcome."],
  };
}

describe("API scan detail tabs", () => {
  it("shows the summary with offline mode and a coverage tab with skipped reasons", async () => {
    const scan: ScanJob = { scan_id: SID, project_id: PID, module: "api_security", profile: "default", state: "completed", revision: 5, created_at: "", updated_at: "", queued_at: "", started_at: "", finished_at: "", targets: ["api-spec"], authorized_targets: [], parameters: {}, progress: { stage: "summary", percent: 100, counters: {} }, cancel_requested: false, warnings: [], errors: [], output_refs: ["work/summary.json", "work/coverage.json"], correlation_id: "c", retry_of: null, final_reason: "completed", scope_hash: null, tool_versions: {} };
    const detail: ScanDetail = { scan, active: false, terminal: true, elapsed_seconds: 2 };
    mockApi({
      ...base,
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: detail },
      [`GET /api/projects/${PID}/scans/${SID}/events`]: { body: { items: [], offset: 0, limit: 200, has_more: false, corrupt_lines: 0 } },
      [`GET /api/projects/${PID}/scans/${SID}/console`]: { body: { lines: [] } },
      [`GET /api/projects/${PID}/scans/${SID}/results/summary`]: { body: apiSummary() },
      [`GET /api/projects/${PID}/scans/${SID}/results/coverage`]: { body: { catalog_version: "1.0.0", results: [{ rule_id: "API-BOLA-000", title: "BOLA/IDOR checks", kind: "active", outcome: "skipped", subject: "-", rationale: "needs two test identities", parameter: "", severity: null, finding_id: null }] } },
      "GET /api/findings": { body: { items: [], total: 0, offset: 0, limit: 100, errors: [] } },
    });
    renderAt(`/projects/${PID}/scans/${SID}`);
    const u = userEvent.setup();
    expect(await screen.findByText("Operations")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Check outcome counts" })).toHaveTextContent(/skipped\s*13/);
    await u.click(screen.getByRole("tab", { name: "Coverage" }));
    const cov = await screen.findByRole("table", { name: "API coverage" });
    expect(cov).toHaveTextContent("API-BOLA-000");
    expect(cov).toHaveTextContent("needs two test identities");
  });
});
