import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AppRoutes, makeQueryClient, Providers } from "../App";
import type { DashboardSummary, Page, ProjectOverview, VersionInfo } from "../api/types";

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

type Handler = (call: Call) => { status?: number; body: unknown } | undefined;

/** Route-level fetch mock. Unmatched requests fail loudly so tests never hit a network. */
export function mockApi(handlers: Record<string, Handler | { status?: number; body: unknown }>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://127.0.0.1");
    const method = (init?.method ?? "GET").toUpperCase();
    const call: Call = {
      method,
      path: url.pathname,
      query: url.searchParams,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    const handler = handlers[`${method} ${url.pathname}`];
    const result = typeof handler === "function" ? handler(call) : handler;
    if (!result) {
      return new Response(JSON.stringify({ error: { code: "not_found", message: `unmocked ${method} ${url.pathname}`, details: [] } }), {
        status: 404,
      });
    }
    return new Response(JSON.stringify(result.body), { status: result.status ?? 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export function renderAt(path: string) {
  const client = makeQueryClient();
  client.setDefaultOptions({ queries: { retry: false, refetchOnWindowFocus: false }, mutations: { retry: false } });
  return render(
    <Providers client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </Providers>,
  );
}

export const VERSION: VersionInfo = {
  name: "VAPT Workbench",
  version: "0.0.1",
  api_version: "1",
  storage_version: 1,
  python: "3.13.5",
  scanning_available: false,
};

const zero = <K extends string>(keys: K[]) => Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>;

export function emptySummary(): DashboardSummary {
  return {
    generated_at: "2026-10-20T00:00:00Z",
    project_id: null,
    projects: { total: 0, active: 0, archived: 0, authorization: zero(["missing", "not_started", "active", "expiring_soon", "expired"]) },
    scans: {
      total: 0,
      active: 0,
      failed: 0,
      by_state: zero(["queued", "validating", "running", "completed", "completed_with_warnings", "failed", "cancelled", "interrupted", "blocked_scope", "expired_authorization"]),
      last_scan_at: null,
      last_scan_state: null,
    },
    findings: {
      total: 0,
      open: 0,
      by_severity: zero(["critical", "high", "medium", "low", "informational"]),
      by_status: zero(["new", "confirmed", "false_positive", "accepted_risk", "fixed", "retest_needed", "needs_review"]),
      by_confidence: zero(["confirmed", "probable", "potential", "needs_review"]),
    },
    assets: { total: 0, by_type: zero(["domain", "hostname", "ip", "port", "service", "url", "api_operation"]) },
    recent_activity: [],
    unreadable_records: 0,
  };
}

export function emptyPage<T>(): Page<T> {
  return { items: [], total: 0, offset: 0, limit: 25, errors: [] };
}

export const PID = "prj_" + "a".repeat(32);

export function overview(overrides: Partial<ProjectOverview["project"]> = {}, extra: Partial<ProjectOverview> = {}): ProjectOverview {
  return {
    project: {
      schema_version: 1,
      project_id: PID,
      revision: 1,
      created_at: "2026-10-01T10:00:00Z",
      updated_at: "2026-10-02T10:00:00Z",
      name: "Web assessment",
      client_name: "Acme Corp",
      description: "",
      status: "active",
      authorization: {
        organization: "Acme Corp",
        target_owner: "Acme IT",
        authorized_by: "CISO",
        reference: "SOW-1",
        window_start: "2026-10-01T00:00:00Z",
        window_end: "2026-12-01T00:00:00Z",
        attestation_event_id: "evt_" + "b".repeat(32),
        notes: "",
      },
      scope: {
        schemes: ["https"],
        hosts: ["app.example.com"],
        wildcard_domains: [],
        ip_ranges: [],
        ports: [443],
        path_prefixes: ["/"],
        api_server_urls: [],
        exclusions: { hosts: [], wildcard_domains: [], ip_ranges: [], ports: [], path_prefixes: [] },
        redirect_policy: "same_scope_only",
        internal_override: null,
      },
      scan_policy: {
        max_concurrency: 2,
        requests_per_second: 2,
        connect_timeout_seconds: 5,
        read_timeout_seconds: 15,
        max_redirects: 5,
        max_crawl_depth: 3,
        max_pages: 200,
        max_response_bytes: 1048576,
        max_duration_seconds: 1800,
        max_requests_per_target: 2000,
        allowed_modules: [],
        active_probes: { sqli_error_differential: false, xss_reflection: false, api_mutating_operations: false, api_idor: false, api_rate_limit_probe: false },
        evidence_retention_days: null,
      },
      labels: [],
      notes: "",
      ...overrides,
    },
    authorization_status: "active",
    authorization_expires_at: "2026-12-01T00:00:00Z",
    last_scan: null,
    counts: { scan: 0, finding: 0, asset: 0, evidence: 0, import: 0, report: 0 },
    ...extra,
  };
}
