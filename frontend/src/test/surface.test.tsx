// Phase 06 UI: surface scan profile in the start dialog, surface detail tabs, asset graph page.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { Asset, ScanDetail, ScanJob, ScopePolicyView, SurfaceProfilePreview, SurfaceSummary, SurfaceView } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "f".repeat(32);

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

function surfacePreview(): SurfaceProfilePreview {
  return {
    problems: [], target_problems: [], nmap: null,
    profile: {
      profile_version: 1, roots: ["lab.test"], manual_hosts: 0, port_method: "auto",
      ports: { requested: [80, 443, 9999], tested: [80, 443], not_tested: { "9999": "not in scope" } },
      max_hosts: 50, probe_web: true, web_max_pages: 5, read_banners: true, tls_verify: true,
      sources: [
        { name: "manual", label: "Targets and manual/imported host list", enabled: true, disclosure: "Local input only." },
        { name: "crtsh", label: "crt.sh (Certificate Transparency logs)", enabled: false, disclosure: "Sends each root to crt.sh, a third-party service." },
      ],
      dns: "OS resolver: A/AAAA and CNAME", limitations: ["No DNS wordlist brute force."],
    },
  };
}

function job(over: Partial<ScanJob> = {}): ScanJob {
  return {
    scan_id: SID, project_id: PID, module: "attack_surface", profile: "default", state: "completed", revision: 9,
    created_at: "2026-11-01T10:00:00Z", updated_at: "2026-11-01T10:02:00Z", queued_at: "2026-11-01T10:00:00Z",
    started_at: "2026-11-01T10:00:01Z", finished_at: "2026-11-01T10:02:00Z", targets: ["lab.test"],
    authorized_targets: ["lab.test"], parameters: {},
    progress: { stage: "summary", percent: 100, counters: {} }, cancel_requested: false, warnings: [], errors: [],
    output_refs: ["work/profile.json", "work/summary.json", "work/coverage.json", "work/inventory.json", "work/changes.json", "work/hosts.json"],
    correlation_id: "c", retry_of: null, final_reason: "completed", scope_hash: "a".repeat(64), tool_versions: {}, ...over,
  };
}

const summary: SurfaceSummary = {
  schema_version: 1, catalog_version: "1.0.0", stopped_early: "", roots: ["lab.test"], candidates: 4,
  candidates_by_status: { in_scope: 2, pending_approval: 1, out_of_scope: 1 }, rejected_inputs: [],
  sources: [{ name: "manual", label: "Manual", candidates: 2, disclosure: "Local input only." }],
  passive_sources_enabled: false,
  dns: { resolved: 2, unresolved: 0, not_attempted: 2, blocked_addresses: 1, method: "OS resolver A/AAAA/CNAME" },
  port_method: "connect", ports_requested: [80, 443, 9999], ports_tested: [80, 443], ports_not_tested: { "9999": "not in scope" },
  hosts_checked: { "lab.test": { ips: ["127.0.0.1"], ports_tested: [80, 443], method: "connect", open: [22] } },
  hosts_not_checked: { "new.lab.test": "pending approval: discovered, not in scope (not scanned)" },
  open_services: [{ host: "lab.test", ip: "127.0.0.1", port: 22, service: "ssh", product: "OpenSSH", version: "8.9", banner: "SSH-2.0-OpenSSH_8.9" }],
  web_origins: [{ origin: "http://lab.test", status: 200, title: "Lab", server: "nginx", error: "", tls: {} }],
  check_outcomes: [{ outcome: "finding", count: 1 }, { outcome: "skipped", count: 3 }],
  findings_created: 1, findings_reobserved: 0, assets_created: 5, assets_updated: 0, tool_versions: {},
  components: [], changes: { baseline: true }, warnings: [], limitations: ["No DNS wordlist brute force."],
};

function detailApi(scan: ScanJob, extra: Record<string, unknown> = {}) {
  const d: ScanDetail = { scan, active: false, terminal: true, elapsed_seconds: 119 };
  return mockApi({
    ...base,
    [`GET /api/projects/${PID}/scans/${SID}`]: { body: d },
    [`GET /api/projects/${PID}/scans/${SID}/events`]: { body: { items: [], offset: 0, limit: 200, has_more: false, corrupt_lines: 0 } },
    [`GET /api/projects/${PID}/scans/${SID}/console`]: { body: { lines: [] } },
    [`GET /api/projects/${PID}/scans/${SID}/results/summary`]: { body: summary },
    [`GET /api/projects/${PID}/scans/${SID}/results/coverage`]: { body: { catalog_version: "1.0.0", results: [{ rule_id: "SURF-SVC-002", title: "Remote administration service reachable", kind: "probe", outcome: "finding", subject: "tcp://lab.test:22", rationale: "ssh reachable", parameter: "22", severity: "low", finding_id: "fnd_1" }] } },
    [`GET /api/projects/${PID}/scans/${SID}/results/changes`]: { body: { baseline: true, previous_scan_id: null, new_hosts: [], not_observed_hosts: [], status_changes: [], ip_changes: [], opened_ports: [], closed_ports: [], new_origins: [], not_observed_origins: [] } },
    "GET /api/findings": { body: { items: [], total: 0, offset: 0, limit: 100, errors: [] } },
    ...(extra as Record<string, { body: unknown }>),
  });
}

describe("attack surface start dialog", () => {
  it("shows the surface plan with tested/untested ports and source disclosure", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
      "GET /api/jobs/modules": { body: [{ module: "attack_surface", label: "Attack surface mapper (Option B)", available: true, reason: "" }] },
      [`GET /api/projects/${PID}/surface-scan-profile`]: { body: surfacePreview() },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Attack surface mapper/ }));
    await u.type(within(card).getByRole("textbox", { name: /targets/i }), "lab.test");
    const plan = await within(card).findByLabelText("Surface scan profile");
    expect(within(plan).getByText(/Ports to test: 80, 443/)).toBeInTheDocument();
    expect(within(plan).getByText(/9999 \(not in scope\)/)).toBeInTheDocument();
    expect(within(plan).getByText(/crt.sh \(Certificate Transparency logs\)/)).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/surface-scan-profile"))).toBe(true));
  });
});

describe("attack surface detail tabs", () => {
  it("shows summary, hosts/ports, origins and coverage", async () => {
    detailApi(job());
    renderAt(`/projects/${PID}/scans/${SID}`);
    const u = userEvent.setup();
    expect(await screen.findByText("Candidates")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Candidate status counts" })).toHaveTextContent(/Pending approval\s*1/);

    await u.click(screen.getByRole("tab", { name: "Hosts / ports" }));
    const svc = await screen.findByRole("table", { name: "Open services" });
    expect(svc).toHaveTextContent("ssh");
    expect(screen.getByText(/pending approval: discovered, not in scope/)).toBeInTheDocument();

    await u.click(screen.getByRole("tab", { name: "Web origins" }));
    expect(await screen.findByRole("table", { name: "Web origins" })).toHaveTextContent("http://lab.test");

    await u.click(screen.getByRole("tab", { name: "Coverage" }));
    expect(await screen.findByRole("table", { name: "Surface coverage" })).toHaveTextContent("SURF-SVC-002");
  });
});

describe("attack surface asset page", () => {
  const assets: SurfaceView = {
    total: 2, truncated: false, counts: { type: { hostname: 1, port: 1 }, status: { in_scope: 1, pending_approval: 1 } },
    edges: [],
    items: [
      { asset: { asset_id: "ast_1", project_id: PID, asset_type: "hostname", locator: "lab.test", scope_status: "in_scope", confidence: "confirmed", last_seen: "2026-11-01T10:00:00Z", revision: 1 } as Asset, candidate_status: "in_scope", priority: 30, priority_factors: ["+20 worst open finding: medium", "+10 database/admin/cleartext service reachable"], findings: 1 },
      { asset: { asset_id: "ast_2", project_id: PID, asset_type: "hostname", locator: "new.lab.test", scope_status: "pending_approval", confidence: "potential", last_seen: "2026-11-01T10:00:00Z", revision: 1 } as Asset, candidate_status: "pending_approval", priority: 0, priority_factors: ["0: discovered only (discovery is not a vulnerability)"], findings: 0 },
    ],
  };

  it("lists assets with transparent priority and an approve button for pending hosts", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/surface`]: { body: assets },
      [`POST /api/projects/${PID}/assets/ast_2/approve`]: { body: overview().project },
    });
    renderAt(`/projects/${PID}/surface`);
    const u = userEvent.setup();
    expect(await screen.findByText("lab.test")).toBeInTheDocument();
    expect(screen.getByText("new.lab.test")).toBeInTheDocument();
    // approve the pending host
    await u.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/assets/ast_2/approve"))).toBe(true));
    const body = calls.find((c) => c.method === "POST")!.body as { confirmed: boolean };
    expect(body.confirmed).toBe(true);
  });
});
