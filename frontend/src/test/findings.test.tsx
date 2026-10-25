// Phase 09 UI: findings workbench (list/filter/sort) and finding detail (triage, comments,
// provenance, risk breakdown, merge/unmerge).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { Finding, FindingDetailView, FindingListItem } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const FID = "fnd_" + "a".repeat(32);
const FID2 = "fnd_" + "b".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    schema_version: 1, finding_id: FID, project_id: PID, revision: 1,
    created_at: "2026-11-01T09:00:00Z", updated_at: "2026-11-02T09:00:00Z",
    scan_id: null, fingerprint: null, rule_id: "WEB-XSS-001", category: "", parameter: "q",
    component: "", title: "Reflected XSS in search", summary: "Unsanitized input reflected.",
    technical_detail: "GET /search?q=<script>", affected_asset_ids: [], method: null,
    severity: "high", confidence: "confirmed", verification_state: "automated_evidence",
    analyst_status: "new", business_impact: "", business_priority: null, evidence_ids: [],
    cwe_ids: [79], mappings: [{ catalog: "cwe", catalog_version: "curated-2026-10-25", entry_id: "CWE-79", title: "Cross-Site Scripting (XSS)", rationale: "Weakness category assigned by the rule catalog", confidence: "confirmed" }],
    cvss: null, remediation: "Encode output.", references: [], sources: [{ tool: "vapt-web-scanner", tool_version: "1.0.0", rule_id: "WEB-XSS-001", source_finding_id: "", original_severity: "", original_confidence: "", import_id: null, scan_id: null, observed_at: "2026-11-01T09:00:00Z" }],
    dedup_history: [], comments: [], merged_into: null, url: "https://app.example.com/search?q=1",
    ...overrides,
  };
}

function listItem(overrides: Partial<FindingListItem> = {}): FindingListItem {
  return {
    finding: finding(), module: "web_app", risk_score: 72.5, risk_tier: "high",
    asset_criticality: null, reviewed: false,
    ...overrides,
  };
}

function detailView(overrides: Partial<FindingDetailView> = {}): FindingDetailView {
  return {
    finding: finding(), module: "web_app",
    risk: {
      severity_points: 75, confidence_multiplier: 1, severity_after_confidence: 75,
      asset_criticality_bonus: 0, exposure_bonus: 10, verification_bonus: 5,
      raw_score: 90, score: 90, tier: "critical", capped_for_needs_review: false,
    },
    assets: [], duplicate_of: null, merged_duplicates: [],
    ...overrides,
  };
}

describe("Findings workbench page", () => {
  it("lists findings with risk/module badges and links to the detail page", async () => {
    mockApi({
      ...base,
      "GET /api/findings": { body: { items: [listItem()], total: 1, offset: 0, limit: 25, errors: [] } },
    });
    renderAt("/findings");
    const table = await screen.findByRole("table", { name: "Findings" });
    expect(table).toHaveTextContent("Reflected XSS in search");
    expect(table).toHaveTextContent("High");
    expect(table).toHaveTextContent("Web app");
    const link = within(table).getByRole("link", { name: "Reflected XSS in search" });
    expect(link).toHaveAttribute("href", `/projects/${PID}/findings/${FID}`);
  });

  it("passes severity/module filters from the URL to the API and shows active scope badges", async () => {
    const { calls } = mockApi({
      ...base,
      "GET /api/findings": { body: { items: [], total: 0, offset: 0, limit: 25, errors: [] } },
    });
    renderAt(`/findings?project_id=${PID}&severity=high&module=web_app`);
    expect(await screen.findByRole("heading", { name: /No findings match/ })).toBeInTheDocument();
    const call = calls.find((c) => c.path === "/api/findings")!;
    expect(call.query.get("project_id")).toBe(PID);
    expect(call.query.getAll("severity")).toEqual(["high"]);
    expect(call.query.getAll("module")).toEqual(["web_app"]);
    expect(screen.getByText(/Project id:/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Clear filters" })).toHaveAttribute("href", "/findings");
  });

  it("shows an empty state with no filter badges when nothing is applied", async () => {
    mockApi({ ...base, "GET /api/findings": { body: { items: [], total: 0, offset: 0, limit: 25, errors: [] } } });
    renderAt("/findings");
    await screen.findByRole("heading", { name: /No findings match|No findings yet/ });
    expect(screen.queryByRole("link", { name: "Clear filters" })).not.toBeInTheDocument();
  });
});

describe("Finding detail page", () => {
  function detailApi(overrides: Partial<FindingDetailView> = {}) {
    return mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/findings/${FID}`]: { body: detailView(overrides) },
      "GET /api/audit": { body: { items: [], offset: 0, limit: 50, has_more: false, corrupt_lines: 0 } },
    });
  }

  it("shows title, risk breakdown, provenance and CWE mapping", async () => {
    detailApi();
    renderAt(`/projects/${PID}/findings/${FID}`);
    expect(await screen.findByRole("heading", { name: "Reflected XSS in search" })).toBeInTheDocument();
    expect(screen.getByText(/critical risk \(90\/100\)/i)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Finding sources" })).toHaveTextContent("vapt-web-scanner");
    expect(screen.getByText(/CWE-79/)).toBeInTheDocument();
    expect(screen.getByText(/Cross-Site Scripting/)).toBeInTheDocument();
  });

  it("saves a triage edit without touching scanner-owned fields", async () => {
    const { calls } = detailApi();
    renderAt(`/projects/${PID}/findings/${FID}`);
    await screen.findByRole("heading", { name: "Reflected XSS in search" });
    const u = userEvent.setup();
    const triage = within(screen.getByRole("region", { name: "Analyst triage" }));
    await u.click(triage.getByLabelText("Status"));
    await u.click(await screen.findByRole("option", { name: "Confirmed" }));
    const impact = triage.getByLabelText("Business impact");
    await u.clear(impact);
    await u.type(impact, "Customer-facing checkout page");
    await u.click(triage.getByRole("button", { name: "Save triage" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH")!;
    const body = patch.body as Record<string, unknown>;
    expect(body.analyst_status).toBe("confirmed");
    expect(body.business_impact).toBe("Customer-facing checkout page");
    expect(body).not.toHaveProperty("severity");
    expect(body).not.toHaveProperty("cwe_ids");
  });

  it("posts a comment", async () => {
    const { calls } = detailApi();
    renderAt(`/projects/${PID}/findings/${FID}`);
    await screen.findByRole("heading", { name: "Reflected XSS in search" });
    const u = userEvent.setup();
    await u.type(screen.getByPlaceholderText("Add a note…"), "Verified manually");
    await u.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/comments"))).toBe(true));
    const commentCall = calls.find((c) => c.path.endsWith("/comments"))!;
    expect((commentCall.body as Record<string, unknown>).text).toBe("Verified manually");
  });

  it("marks a finding as a duplicate and can unmerge it", async () => {
    const { calls } = detailApi();
    renderAt(`/projects/${PID}/findings/${FID}`);
    await screen.findByRole("heading", { name: "Reflected XSS in search" });
    const u = userEvent.setup();
    await u.click(screen.getByRole("button", { name: "Mark as duplicate…" }));
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByLabelText("Canonical finding ID"), FID2);
    await u.click(within(dialog).getByRole("button", { name: "Merge" }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/merge"))).toBe(true));
    const mergeCall = calls.find((c) => c.path.endsWith("/merge"))!;
    expect((mergeCall.body as Record<string, unknown>).into_finding_id).toBe(FID2);
  });

  it("shows an unmerge affordance when already merged", async () => {
    const { calls } = detailApi({ finding: finding({ merged_into: FID2 }) });
    renderAt(`/projects/${PID}/findings/${FID}`);
    await screen.findByRole("heading", { name: "Reflected XSS in search" });
    expect(screen.getByText(/This finding is merged/)).toBeInTheDocument();
    const u = userEvent.setup();
    await u.click(screen.getByRole("button", { name: "Unmerge" }));
    await waitFor(() => expect(calls.some((c) => c.path.endsWith("/unmerge"))).toBe(true));
  });

  it("renders a comment and a business-impact field containing markup as literal text", async () => {
    const xss = "<script>window.__pwned = true</script><img src=x onerror=alert(1)>";
    detailApi({
      finding: finding({
        business_impact: xss,
        comments: [{ comment_id: "cmt_" + "c".repeat(32), author: "local-operator", text: xss, created_at: "2026-11-02T10:00:00Z" }],
      }),
    });
    renderAt(`/projects/${PID}/findings/${FID}`);
    await screen.findByRole("heading", { name: "Reflected XSS in search" });
    const region = screen.getByRole("region", { name: "Comments" });
    expect(region).toHaveTextContent(xss);
    expect(document.querySelector("script[src], img[onerror]")).toBeNull();
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
  });
});
