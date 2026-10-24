// Phase 08 UI: Import Center — upload preview, duplicate review, explicit commit.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ImportDetail, ImportFormats, ImportSummary } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const IMP = "imp_" + "a".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
  [`GET /api/projects/${PID}`]: { body: overview() },
};

function formats(): ImportFormats {
  return {
    supported: [{ source_type: "generic_json", label: "Generic JSON" }],
    unsupported: [{ source_type: "zap", reason: "ZAP export schema varies across versions." }],
  };
}

function summary(overrides: Partial<ImportSummary> = {}): ImportSummary {
  return {
    import_id: IMP, revision: 1, display_filename: "findings.json", sha256: "a".repeat(64),
    size_bytes: 512, source_type: "generic_json", source_tool_version: "", status: "parsed",
    uploaded_at: "2026-11-01T10:00:00Z", parser_version: "vapt-import-generic-json 1.0.0",
    warnings: [], record_count: 1, mapped_count: 0, rejected_count: 1,
    ...overrides,
  };
}

function detail(): ImportDetail {
  return {
    summary: summary(),
    error: "",
    preview: {
      source_type: "generic_json", label: "Generic JSON", parser_version: "vapt-import-generic-json 1.0.0",
      source_tool_version: "", parsed_count: 1, rejected_count: 1,
      warnings: ["record 2: no usable title field; skipped"],
      records: [{ index: 0, title: "Reflected XSS", severity: "high", confidence: "probable", host: "10.0.0.6", url: null, rule_id: "", action: "new", existing_finding_id: null, duplicate_of_index: null }],
      duplicate_candidates: [{ title: "Reflected XSS", index_a: 0, index_b: null, existing_finding_id: "fnd_" + "b".repeat(32) }],
      mapping_gaps: [], asset_count: 0, truncated_sample: false,
    },
  };
}

describe("Import Center page", () => {
  it("lists imports, shows the dry-run preview with duplicate warnings, and commits on request", async () => {
    const { calls } = mockApi({
      ...base,
      "GET /api/imports/formats": { body: formats() },
      [`GET /api/projects/${PID}/imports`]: { body: [summary()] },
      [`GET /api/projects/${PID}/imports/${IMP}`]: { body: detail() },
      [`POST /api/projects/${PID}/imports/${IMP}/commit`]: {
        body: { import_id: IMP, findings_created: 1, findings_reobserved: 0, assets_created: 0, assets_updated: 0 },
      },
    });
    renderAt(`/projects/${PID}/imports`);
    const u = userEvent.setup();

    expect(await screen.findByText("Generic JSON")).toBeInTheDocument(); // supported formats badge
    expect(screen.getByText(/ZAP export schema varies/)).toBeInTheDocument();
    expect(await screen.findByText("findings.json")).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Review" }));
    const table = await screen.findByRole("table", { name: "Parsed findings preview" });
    expect(table).toHaveTextContent("Reflected XSS");
    expect(screen.getByText(/no usable title field/)).toBeInTheDocument();
    expect(screen.getByText(/matches an existing finding by title only/)).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Commit to project" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/commit"))).toBe(true));
    const commitCall = calls.find((c) => c.method === "POST" && c.path.endsWith("/commit"))!;
    expect(commitCall.body).toEqual({ confirmed: true, expected_revision: 1 });
    expect(await screen.findByText(/1 new finding/)).toBeInTheDocument();
  });

  it("renders an imported title containing markup as literal text, never as HTML", async () => {
    const xssTitle = "<script>window.__pwned = true</script><img src=x onerror=alert(1)>";
    mockApi({
      ...base,
      "GET /api/imports/formats": { body: formats() },
      [`GET /api/projects/${PID}/imports`]: { body: [summary()] },
      [`GET /api/projects/${PID}/imports/${IMP}`]: {
        body: {
          ...detail(),
          preview: {
            ...detail().preview!,
            records: [{ index: 0, title: xssTitle, severity: "high", confidence: "probable", host: "10.0.0.6", url: null, rule_id: "", action: "new", existing_finding_id: null, duplicate_of_index: null }],
            duplicate_candidates: [],
          },
        },
      },
    });
    renderAt(`/projects/${PID}/imports`);
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Review" }));
    const table = await screen.findByRole("table", { name: "Parsed findings preview" });
    // The literal payload appears as plain text in the cell...
    expect(table).toHaveTextContent(xssTitle);
    // ...and was never parsed as markup: no <script>/<img> element was actually inserted.
    expect(document.querySelector("script[src], img[onerror]")).toBeNull();
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
  });

  it("shows mapping gaps and a within-file duplicate as distinct from a new finding", async () => {
    mockApi({
      ...base,
      "GET /api/imports/formats": { body: formats() },
      [`GET /api/projects/${PID}/imports`]: { body: [summary()] },
      [`GET /api/projects/${PID}/imports/${IMP}`]: {
        body: {
          ...detail(),
          preview: {
            ...detail().preview!,
            mapping_gaps: ["severity", "remediation"],
            records: [
              { index: 0, title: "Outdated jQuery", severity: "medium", confidence: "probable", host: "10.0.0.3", url: null, rule_id: "CVE-1", action: "new", existing_finding_id: null, duplicate_of_index: null },
              { index: 1, title: "Outdated jQuery (dup)", severity: "medium", confidence: "probable", host: "10.0.0.3", url: null, rule_id: "CVE-1", action: "duplicate_in_import", existing_finding_id: null, duplicate_of_index: 0 },
            ],
            duplicate_candidates: [],
          },
        },
      },
    });
    renderAt(`/projects/${PID}/imports`);
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Review" }));
    expect(await screen.findByText(/Mapping gaps/)).toBeInTheDocument();
    expect(screen.getByText(/severity, remediation/)).toBeInTheDocument();
    expect(screen.getByText(/duplicate of row 1 in this file/)).toBeInTheDocument();
  });

  it("shows the parser error inline when a file cannot be detected, without listing a preview", async () => {
    mockApi({
      ...base,
      "GET /api/imports/formats": { body: formats() },
      [`GET /api/projects/${PID}/imports`]: { body: [summary({ status: "parse_failed", record_count: 0, rejected_count: 0 })] },
      [`GET /api/projects/${PID}/imports/${IMP}`]: {
        body: { summary: summary({ status: "parse_failed", record_count: 0, rejected_count: 0 }), preview: null, error: "could not detect the report format" },
      },
    });
    renderAt(`/projects/${PID}/imports`);
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Review" }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(/could not detect the report format/)).toBeInTheDocument();
  });
});
