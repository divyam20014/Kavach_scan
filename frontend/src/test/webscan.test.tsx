// Phase 05 UI: web scan profile in the start dialog, scan detail tabs, findings filter.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { CoverageRow, PagesInventory, ScanDetail, ScanJob, ScopePolicyView, WebProfilePreview, WebScanSummary, ZapScanSummary } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "e".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

function policy(): ScopePolicyView {
  return {
    project_id: PID, scope: overview().project.scope, scope_hash: "a".repeat(64), valid: true,
    authorization: { decision_id: "d", at: "", allowed: true, reason: "allowed", message: "Authorization is active", check: "authorization", input: "", target: null, ip: null, rule: null, project_id: PID, scope_hash: null },
    can_start_active_work: true, internal_override: null, warnings: [], blocked_ranges: [],
  };
}

function preview(problems: string[] = []): WebProfilePreview {
  return {
    problems,
    tls_tools: [],
    parameters: {},
    profile: {
      profile_version: 1, catalog_version: "1.0.0", safe_mode: true, engine: "native", auth_scheme: "none", auth_header_name: "Authorization", respect_robots: true, tls_verify: true, seed_paths: [],
      budgets: { max_pages: 200, max_depth: 3, requests_per_second: 2, max_concurrency: 2, max_requests_per_target: 2000, max_duration_seconds: 1800, max_response_bytes: 1048576, max_redirects: 5 },
      checks: [
        { group: "headers", label: "Security headers", kind: "passive", rule_ids: ["WEB-HDR-001"], enabled: true, reason: "" },
        { group: "cors", label: "CORS policy", kind: "probe", rule_ids: ["WEB-CORS-001"], enabled: true, reason: "" },
        { group: "active_injection", label: "Active SQL injection / XSS testing", kind: "tool", rule_ids: ["WEB-INJ-000"], enabled: false, reason: "Not built in: use imported results from a dedicated tool" },
      ],
      limitations: ["Active injection testing is not built in."],
      zap_spider_max_minutes: 2, zap_wait_max_minutes: 2,
    },
  };
}

function job(over: Partial<ScanJob> = {}): ScanJob {
  return {
    scan_id: SID, project_id: PID, module: "web_app", profile: "default", state: "completed_with_warnings", revision: 9,
    created_at: "2026-11-01T10:00:00Z", updated_at: "2026-11-01T10:02:00Z", queued_at: "2026-11-01T10:00:00Z",
    started_at: "2026-11-01T10:00:01Z", finished_at: "2026-11-01T10:02:00Z", targets: ["https://app.example.com/"],
    authorized_targets: ["https://app.example.com/"], parameters: {},
    progress: { stage: "summary", percent: 100, counters: { pages_fetched: 2, requests_sent: 5 } },
    cancel_requested: false, warnings: ["Crawl incomplete: page limit (2) reached"], errors: [],
    output_refs: ["work/profile.json", "work/summary.json", "work/coverage.json", "work/pages.json"],
    correlation_id: "c", retry_of: null, final_reason: "completed with warnings", scope_hash: "a".repeat(64), tool_versions: {}, ...over,
  };
}

const summary: WebScanSummary = {
  schema_version: 1, catalog_version: "1.0.0", safe_mode: true, stopped_early: "", targets: ["https://app.example.com/"],
  pages_fetched: 2, endpoints_discovered: 2, forms_discovered: 1, parameters_discovered: 1, requests_sent: 5, request_errors: 0,
  request_retries: 0, rate_limited_responses: 1, scope_blocked: 1, redirects_blocked: 1, out_of_scope_links: 3,
  out_of_scope_hosts: { "outside.example": 3 }, crawl_skipped: { robots_disallowed: 1 }, crawl_limit: "page limit (2) reached",
  robots: { "https://app.example.com": "honoured" }, check_outcomes: [{ outcome: "pass", count: 7 }, { outcome: "observation", count: 2 }, { outcome: "finding", count: 3 }, { outcome: "skipped", count: 4 }, { outcome: "error", count: 1 }],
  findings_created: 3, findings_reobserved: 0, findings_by_severity: { low: 3 }, tool_versions: {},
  components: [{ name: "nginx", version: "1.18.0", confidence: "probable", sources: ["Server header"], evidence: [] }],
  warnings: [], limitations: ["Active injection testing is not built in: no SQL injection or XSS test input is sent."],
};

const coverage: { catalog_version: string; results: CoverageRow[] } = {
  catalog_version: "1.0.0",
  results: [
    { rule_id: "WEB-HDR-003", title: "X-Content-Type-Options header missing", kind: "passive", outcome: "finding", subject: "https://app.example.com", rationale: "response without nosniff", parameter: "", severity: "low", finding_id: "fnd_1" },
    { rule_id: "WEB-TLS-006", title: "TLS protocol and cipher analysis", kind: "tool", outcome: "skipped", subject: "https://app.example.com", rationale: "neither sslyze nor testssl.sh is installed", parameter: "", severity: null, finding_id: null },
    { rule_id: "WEB-HDR-001", title: "Strict-Transport-Security header missing", kind: "passive", outcome: "pass", subject: "https://app.example.com", rationale: "control present in 2 response(s) examined", parameter: "", severity: null, finding_id: null },
  ],
};

const pages: PagesInventory = {
  pages: [
    { url: "https://app.example.com/", depth: 0, status: 200, content_type: "text/html", title: "Home", bytes: 900, truncated: false, final_url: "https://app.example.com/", redirect_chain: [], redirect_blocked_to: "", parameters: [], links_found: 4, forms: 1, error: "", source: "target" },
    { url: "https://app.example.com/go?next=x", depth: 1, status: 302, content_type: "", title: "", bytes: 0, truncated: false, final_url: "https://app.example.com/go?next=x", redirect_chain: [], redirect_blocked_to: "https://evil.example/", parameters: ["next"], links_found: 0, forms: 0, error: "", source: "crawl" },
  ],
  forms: [{ page: "https://app.example.com/", action: "https://app.example.com/login", method: "POST", fields: ["user", "pw"], login_form: true }],
  parameters: ["/go?next"],
  resources: [],
};

function detailApi(scan: ScanJob, extra: Record<string, unknown> = {}) {
  const d: ScanDetail = { scan, active: false, terminal: true, elapsed_seconds: 119 };
  return mockApi({
    ...base,
    [`GET /api/projects/${PID}/scans/${SID}`]: { body: d },
    [`GET /api/projects/${PID}/scans/${SID}/events`]: { body: { items: [], offset: 0, limit: 200, has_more: false, corrupt_lines: 0 } },
    [`GET /api/projects/${PID}/scans/${SID}/console`]: { body: { lines: [] } },
    [`GET /api/projects/${PID}/scans/${SID}/results/summary`]: { body: summary },
    [`GET /api/projects/${PID}/scans/${SID}/results/coverage`]: { body: coverage },
    [`GET /api/projects/${PID}/scans/${SID}/results/pages`]: { body: pages },
    "GET /api/findings": {
      body: {
        items: [{
          finding: { finding_id: "fnd_1", project_id: PID, scan_id: SID, title: "X-Content-Type-Options header missing", severity: "low", confidence: "confirmed", analyst_status: "new", url: "https://app.example.com", rule_id: "WEB-HDR-003", updated_at: "2026-11-01T10:02:00Z" },
          module: "web_app", risk_score: 20, risk_tier: "low", asset_criticality: null, reviewed: false,
        }],
        total: 1, offset: 0, limit: 100, errors: [],
      },
    },
    ...(extra as Record<string, { body: unknown }>),
  });
}

describe("web scan start dialog", () => {
  it("shows the profile (enabled/disabled checks, budgets, safe mode, auth) and sends options", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [{ module: "web_app", label: "Web application scanner (Option A)", available: true, reason: "" }] },
      [`GET /api/projects/${PID}/web-scan-profile`]: { body: preview() },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: job({ state: "queued" }) },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: job({ state: "queued" }), active: false, terminal: false, elapsed_seconds: null } },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Web application scanner/ }));
    const profile = await within(card).findByLabelText("Web scan profile details");
    expect(within(profile).getByText("Safe mode: on")).toBeInTheDocument();
    expect(within(profile).getByText(/Authentication: none/)).toBeInTheDocument();
    expect(within(profile).getByRole("table", { name: "Enabled checks" })).toHaveTextContent("Security headers");
    expect(within(profile).getByRole("table", { name: "Disabled checks" })).toHaveTextContent(/Not built in/);
    expect(within(profile).getByText(/200 pages · depth 3/)).toBeInTheDocument();
    expect(within(profile).getByText(/TLS tools detected: none \(protocol\/cipher checks will be reported as skipped\)/)).toBeInTheDocument();
    await u.click(within(card).getByRole("button", { name: "Advanced options" }));
    await u.click(within(card).getByRole("switch", { name: /CORS check/ }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/web-scan-profile") && c.query.get("check_cors") === "false")).toBe(true));
    await u.type(within(card).getByRole("textbox", { name: /targets/i }), "https://app.example.com/");
    await u.click(within(card).getByRole("button", { name: /Review & confirm/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/no injection test input is sent/)).toBeInTheDocument();
    await u.click(within(dialog).getByRole("checkbox", { name: /I confirm/ }));
    await u.click(within(dialog).getByRole("button", { name: "Start job" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const body = calls.find((c) => c.method === "POST")!.body as { module: string; parameters: Record<string, unknown> };
    expect(body.module).toBe("web_app");
    expect(body.parameters).toEqual({ check_cors: false });
  });

  it("selecting the ZAP engine hides native options and sends engine=zap", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [{ module: "web_app", label: "Web application scanner (Option A)", available: true, reason: "" }] },
      [`GET /api/projects/${PID}/web-scan-profile`]: { body: preview() },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: job({ state: "queued" }) },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: job({ state: "queued" }), active: false, terminal: false, elapsed_seconds: null } },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Web application scanner/ }));
    await within(card).findByLabelText("Web scan profile details");
    await u.click(within(card).getByLabelText("Scan engine"));
    await u.click(await screen.findByRole("option", { name: /OWASP ZAP/ }));
    await u.click(within(card).getByRole("button", { name: "Advanced options" }));
    // native-only controls disappear once ZAP is selected
    expect(within(card).queryByRole("switch", { name: /CORS check/ })).not.toBeInTheDocument();
    expect(within(card).getByLabelText(/Spider duration/)).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/web-scan-profile") && c.query.get("engine") === "zap")).toBe(true));
    await u.type(within(card).getByRole("textbox", { name: /targets/i }), "https://app.example.com/");
    await u.click(within(card).getByRole("button", { name: /Review & confirm/ }));
    const dialog = await screen.findByRole("dialog");
    await u.click(within(dialog).getByRole("checkbox", { name: /I confirm/ }));
    await u.click(within(dialog).getByRole("button", { name: "Start job" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const body = calls.find((c) => c.method === "POST")!.body as { parameters: Record<string, unknown> };
    expect(body.parameters).toEqual({ engine: "zap" });
  });

  it("blocks review when the options are invalid", async () => {
    mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [{ module: "web_app", label: "Web application scanner (Option A)", available: true, reason: "" }] },
      [`GET /api/projects/${PID}/web-scan-profile`]: { body: preview(["seed paths must be relative paths starting with '/'"]) },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Web application scanner/ }));
    expect(await within(card).findByRole("alert")).toHaveTextContent(/seed paths must be relative/);
    await u.type(within(card).getByRole("textbox", { name: /targets/i }), "https://app.example.com/");
    expect(within(card).getByRole("button", { name: /Review & confirm/ })).toBeDisabled();
  });
});

describe("web scan detail tabs", () => {
  it("shows summary, pages, findings, warnings and coverage", async () => {
    detailApi(job());
    renderAt(`/projects/${PID}/scans/${SID}`);
    const u = userEvent.setup();
    expect(await screen.findByRole("table", { name: "Check outcome counts" })).toHaveTextContent(/skipped\s*4/);
    expect(screen.getByRole("table", { name: "Detected components" })).toHaveTextContent("nginx");
    expect(screen.getByRole("row", { name: /pass\s*7/ })).toBeInTheDocument();
    expect(screen.getByText(/Tool versions: no external tool ran/)).toBeInTheDocument();

    await u.click(screen.getByRole("tab", { name: "Pages / endpoints" }));
    const table = await screen.findByRole("table", { name: "Pages and endpoints" });
    expect(table).toHaveTextContent("Home");
    expect(table).toHaveTextContent(/blocked \(out of scope\): https:\/\/evil.example\//);
    expect(screen.getByText(/POST https:\/\/app.example.com\/login — fields: user, pw \(login form\)/)).toBeInTheDocument();

    await u.click(screen.getByRole("tab", { name: "Findings" }));
    expect(await screen.findByRole("table", { name: "Findings from this job" })).toHaveTextContent("WEB-HDR-003");
    expect(screen.getByRole("link", { name: /global findings view/ })).toHaveAttribute("href", `/findings?project_id=${PID}&scan_id=${SID}`);

    await u.click(screen.getByRole("tab", { name: /Warnings/ }));
    expect(await screen.findByText(/Out-of-scope host outside.example: 3 link\(s\), not requested/)).toBeInTheDocument();
    expect(screen.getByText(/no SQL injection or XSS test input is sent/)).toBeInTheDocument();

    await u.click(screen.getByRole("tab", { name: "Coverage" }));
    const cov = await screen.findByRole("table", { name: "Check coverage" });
    expect(cov).toHaveTextContent("neither sslyze nor testssl.sh is installed");
    const tlsRow = within(cov).getByText("WEB-TLS-006").closest("tr")!;
    expect(tlsRow).toHaveTextContent("– skipped");
    expect(tlsRow).not.toHaveTextContent("✓ pass");
    await u.click(screen.getByRole("radio", { name: "Skipped" }));
    expect(screen.getByRole("table", { name: "Check coverage" })).not.toHaveTextContent("WEB-HDR-001");
  });

  it("shows the ZAP summary panel and hides native-only tabs for engine=zap", async () => {
    const zapSummary: ZapScanSummary = {
      engine: "zap", zap_version: "2.17.0", targets: ["https://app.example.com/"],
      alerts_found: 2, findings_created: 2, findings_reobserved: 0,
      limitations: ["Baseline/Passive profile only: bounded spider plus passive analysis."],
    };
    detailApi(
      job({
        parameters: { engine: "zap" },
        output_refs: ["work/profile.json", "work/zap-plan.yaml", "work/zap_summary.json"],
      }),
      { [`GET /api/projects/${PID}/scans/${SID}/results/zap_summary`]: { body: zapSummary } },
    );
    renderAt(`/projects/${PID}/scans/${SID}`);
    expect(await screen.findByText(/OWASP ZAP 2.17.0 — Baseline\/Passive/)).toBeInTheDocument();
    expect(screen.getByText(/Alerts found/)).toBeInTheDocument();
    expect(screen.getByText(/bounded spider plus passive analysis/)).toBeInTheDocument();
    // the native-only tabs never appear for a ZAP-engine scan
    expect(screen.queryByRole("tab", { name: "Pages / endpoints" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Coverage" })).not.toBeInTheDocument();
    // findings still work: they are queried by scan_id, independent of the engine
    expect(screen.getByRole("tab", { name: "Findings" })).toBeInTheDocument();
  });

  it("shows the repo_scan summary panel and hides web-only tabs for module=repo_scan", async () => {
    const repoScanSummary = {
      engines: {
        semgrep: { status: "completed", findings: 2, errors: ["Could not parse broken.py: syntax error at line 3"] },
        gitleaks: { status: "completed", findings: 1 },
        trivy: { status: "failed", error: "trivy exited with status 1" },
      },
      findings_created: 3,
      findings_reobserved: 0,
      limitations: ["Static analysis only: a pattern match is never confirmed as exploitable."],
    };
    detailApi(
      job({
        module: "repo_scan",
        targets: ["repo-scan"],
        authorized_targets: ["repo-scan"],
        parameters: { engines: ["semgrep", "gitleaks", "trivy"] },
        output_refs: ["work/profile.json", "work/repo_scan_summary.json"],
      }),
      { [`GET /api/projects/${PID}/scans/${SID}/results/repo_scan_summary`]: { body: repoScanSummary } },
    );
    renderAt(`/projects/${PID}/scans/${SID}`);
    expect(await screen.findByText(/Static analysis only/)).toBeInTheDocument();
    expect(screen.getByText("Semgrep")).toBeInTheDocument();
    expect(screen.getByText("trivy exited with status 1")).toBeInTheDocument();
    // Semgrep's own `errors` list (files it could not parse) is surfaced, not dropped
    expect(screen.getByText(/Could not parse broken.py/)).toBeInTheDocument();
    // web-only and surface-only tabs never appear for a repo_scan job
    expect(screen.queryByRole("tab", { name: "Pages / endpoints" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Coverage" })).not.toBeInTheDocument();
    // findings still work: they are queried by scan_id, independent of module
    expect(screen.getByRole("tab", { name: "Findings" })).toBeInTheDocument();
  });

  it("filters the global findings view by scan", async () => {
    const { calls } = detailApi(job());
    renderAt(`/findings?project_id=${PID}&scan_id=${SID}`);
    expect(await screen.findByText(/Scan id: scn_eeeeeeee…/)).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.path === "/api/findings" && c.query.get("scan_id") === SID)).toBe(true));
  });

  it("explains that results arrive when the job finishes", async () => {
    mockApi({
      ...base,
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: job({ state: "running", output_refs: [], finished_at: null }), active: true, terminal: false, elapsed_seconds: 3 } },
      [`GET /api/projects/${PID}/scans/${SID}/events`]: { body: { items: [], offset: 0, limit: 200, has_more: false, corrupt_lines: 0 } },
      [`GET /api/projects/${PID}/scans/${SID}/console`]: { body: { lines: [] } },
    });
    renderAt(`/projects/${PID}/scans/${SID}`);
    expect(await screen.findByText(/Results are written when the job finishes/)).toBeInTheDocument();
  });
});
