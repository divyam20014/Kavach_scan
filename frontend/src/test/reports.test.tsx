// Phase 10 UI: report builder (preview/generate consistency, HTML-injection safety) and
// the backup/restore card (upload preview -> conflict -> overwrite -> restore).
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { BackupPreviewResponse, ReportPreviewResponse, ReportSummary, RestoreResponse } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const RPT = "rpt_" + "c".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
  [`GET /api/projects/${PID}`]: { body: overview() },
};

function preview(overrides: Partial<ReportPreviewResponse> = {}): ReportPreviewResponse {
  return {
    finding_ids: ["fnd_" + "a".repeat(32)],
    asset_ids: ["ast_" + "b".repeat(32)],
    scan_ids: [],
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
    status_counts: { new: 1 },
    module_counts: { web_app: 1 },
    limitations: ["This report reflects only the checks that were actually executed."],
    tool_versions: {},
    ...overrides,
  };
}

function summary(overrides: Partial<ReportSummary> = {}): ReportSummary {
  return {
    report_id: RPT, project_id: PID, title: "VAPT Assessment Report", classification_label: "CONFIDENTIAL",
    formats: ["html", "pdf"], finding_count: 1, asset_count: 1, evidence_included: true,
    created_at: "2026-11-02T10:00:00Z",
    ...overrides,
  };
}

describe("Report builder page", () => {
  it("previews and generates with the same finding count, and lists the generated report for download", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}/reports`]: { body: [] },
      [`POST /api/projects/${PID}/reports/preview`]: { body: preview() },
      [`POST /api/projects/${PID}/reports`]: { body: summary() },
    });
    renderAt(`/projects/${PID}/reports`);
    const u = userEvent.setup();

    await u.click(await screen.findByRole("button", { name: "Preview" }));
    expect(await screen.findByText(/Preview — 1 finding\(s\), 1 asset\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/High: 1/)).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Generate report" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/reports"))).toBe(true));
    const genCall = calls.find((c) => c.method === "POST" && c.path.endsWith("/reports"))!;
    expect(genCall.body).toMatchObject({ formats: ["html", "pdf"] });
    expect(await screen.findByText("Report generated")).toBeInTheDocument();
  });

  it("renders a generated report title containing markup as literal text, never as HTML", async () => {
    const xssTitle = "<script>window.__rptpwned = true</script><img src=x onerror=alert(1)>";
    mockApi({
      ...base,
      [`GET /api/projects/${PID}/reports`]: { body: [summary({ title: xssTitle })] },
    });
    renderAt(`/projects/${PID}/reports`);
    const table = await screen.findByRole("table", { name: "Generated reports" });
    expect(table).toHaveTextContent(xssTitle);
    expect(document.querySelector("script[src], img[onerror]")).toBeNull();
    expect((window as unknown as { __rptpwned?: boolean }).__rptpwned).toBeUndefined();
  });

  it("escapes an injected limitation string from the preview response instead of rendering it as markup", async () => {
    const xss = "<img src=x onerror=alert(1)>no-secure-claim";
    mockApi({
      ...base,
      [`GET /api/projects/${PID}/reports`]: { body: [] },
      [`POST /api/projects/${PID}/reports/preview`]: { body: preview({ limitations: [xss] }) },
    });
    renderAt(`/projects/${PID}/reports`);
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Preview" }));
    expect(await screen.findByText(xss)).toBeInTheDocument();
    expect(document.querySelector("img[onerror]")).toBeNull();
  });
});

describe("Backup & restore card", () => {
  function backupPreview(overrides: Partial<BackupPreviewResponse> = {}): BackupPreviewResponse {
    return {
      project_id: PID, project_name: "Web assessment", exported_at: "2026-11-02T10:00:00Z",
      app_version: "0.0.1", storage_version: 1, include_evidence_blobs: true,
      counts: { findings: 3, assets: 2 }, checksum_mismatches: [], project_already_exists: false,
      warnings: [],
      ...overrides,
    };
  }

  function uploadedFile(): File {
    return new File(["PK\x03\x04zip-bytes"], "backup.zip", { type: "application/zip" });
  }

  it("previews an uploaded archive and restores it", async () => {
    const { calls } = mockApi({
      "GET /api/version": { body: VERSION },
      "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
      "POST /api/backup/preview": { body: backupPreview() },
      "POST /api/backup/restore": { body: { project_id: PID, counts: { findings: 3 } } satisfies RestoreResponse },
    });
    renderAt("/settings");
    const u = userEvent.setup();

    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await u.upload(input, uploadedFile());

    expect(await screen.findByText("Web assessment")).toBeInTheDocument();
    expect(screen.getByText(/findings: 3/)).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/api/backup/restore")).toBe(true));
    const restoreCall = calls.find((c) => c.method === "POST" && c.path === "/api/backup/restore")!;
    expect(restoreCall.query.get("confirmed")).toBe("true");
    expect(restoreCall.query.get("overwrite")).toBe("false");
  });

  it("blocks restore on checksum mismatch, and requires an explicit overwrite confirmation when the project already exists", async () => {
    mockApi({
      "GET /api/version": { body: VERSION },
      "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
      "POST /api/backup/preview": { body: backupPreview({ checksum_mismatches: ["manifest.json"] }) },
    });
    renderAt("/settings");
    const u = userEvent.setup();
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await u.upload(input, uploadedFile());

    expect(await screen.findByText("Checksum mismatch")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restore" })).toBeDisabled();
  });

  it("requires the overwrite checkbox before restoring into an existing project id", async () => {
    mockApi({
      "GET /api/version": { body: VERSION },
      "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
      "POST /api/backup/preview": { body: backupPreview({ project_already_exists: true }) },
    });
    renderAt("/settings");
    const u = userEvent.setup();
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await u.upload(input, uploadedFile());

    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
    const restoreBtn = screen.getByRole("button", { name: "Restore" });
    expect(restoreBtn).toBeDisabled();

    await u.click(screen.getByLabelText("Overwrite the existing project"));
    expect(restoreBtn).toBeEnabled();
  });
});
