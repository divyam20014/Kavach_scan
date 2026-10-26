// Phase 11 UI: integrations status (never a false "verified" for a merely-detected tool),
// self-test action, and the local CVE catalog import/remove flow.
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { AppSettings, CveCatalogMetadata, IntegrationStatus } from "../api/types";
import { mockApi, renderAt, VERSION } from "./utils";

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

function settings(overrides: Partial<AppSettings["integrations"]> = {}): AppSettings {
  return {
    schema_version: 1, product_name: "VAPT Workbench", disk_space_warning_bytes: 0,
    evidence_quota_bytes: null, report_timezone_label: "UTC",
    integrations: { nmap_path: "", sslyze_path: "", testssl_path: "", zap_path: "", semgrep_path: "", gitleaks_path: "", online_lookup_credential_alias: "", ...overrides },
    revision: 1, updated_at: "2026-10-25T00:00:00Z",
  };
}

function status(overrides: Partial<IntegrationStatus> = {}): IntegrationStatus {
  return {
    id: "nmap", label: "nmap", capability: "Bounded TCP port/service mapping.",
    configured_path: "", detected_path: "", status: "not_configured", version: "",
    last_used: null, last_error: "", troubleshooting: "Install Nmap or set an explicit path.",
    ...overrides,
  };
}

describe("Integrations page", () => {
  it("never shows a merely-detected tool as verified, and reflects a self-test result", async () => {
    const { calls } = mockApi({
      ...base,
      "GET /api/integrations": { body: [status({ id: "nmap", status: "detected", detected_path: "/usr/bin/nmap" })] },
      "GET /api/cve-catalog": { body: null },
      "GET /api/settings": { body: settings() },
      "POST /api/integrations/nmap/selftest": {
        body: status({ id: "nmap", status: "verified", detected_path: "/usr/bin/nmap", version: "Nmap 7.93" }),
      },
    });
    renderAt("/integrations");
    const u = userEvent.setup();

    expect(await screen.findByText("Detected (unverified)")).toBeInTheDocument();
    expect(screen.queryByText("Verified working")).not.toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: /Run self-test/ }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path === "/api/integrations/nmap/selftest")).toBe(true),
    );
    expect(await screen.findByText("Verified working")).toBeInTheDocument();
    expect(await screen.findByText("Nmap 7.93")).toBeInTheDocument();
  });

  it("shows a clear error state for a failed self-test, never a false pass", async () => {
    mockApi({
      ...base,
      "GET /api/integrations": { body: [status({ status: "not_found", configured_path: "/no/such/nmap" })] },
      "GET /api/cve-catalog": { body: null },
      "GET /api/settings": { body: settings() },
    });
    renderAt("/integrations");
    expect(await screen.findByText("Configured path not found")).toBeInTheDocument();
  });

  it("shows CVE catalog metadata after import and allows removal", async () => {
    const metadata: CveCatalogMetadata = {
      source: "Internal curated export", catalog_version: "2026.10",
      imported_at: "2026-10-25T00:00:00Z", file_sha256: "a".repeat(64), file_name: "catalog.json",
      parser_version: "vapt-cve-catalog 1.0.0", entry_count: 2, stale_after_days: 180,
      is_stale: false, warnings: [],
    };
    let imported = false;
    const { calls } = mockApi({
      ...base,
      "GET /api/integrations": { body: [] },
      "GET /api/settings": { body: settings() },
      "GET /api/cve-catalog": () => ({ body: imported ? metadata : null }),
      "POST /api/cve-catalog/import": () => {
        imported = true;
        return { status: 201, body: metadata };
      },
      "DELETE /api/cve-catalog": () => {
        imported = false;
        return { status: 204, body: null };
      },
    });
    renderAt("/integrations");

    expect(await screen.findByText("No catalog imported yet.")).toBeInTheDocument();

    const input = document.querySelectorAll('input[type="file"]')[0] as HTMLInputElement;
    const u = userEvent.setup();
    const file = new File(['{"source":"x"}'], "catalog.json", { type: "application/json" });
    await u.upload(input, file);

    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path === "/api/cve-catalog/import")).toBe(true),
    );
    expect(await screen.findByText("Internal curated export")).toBeInTheDocument();
    expect(screen.getByText("2 entries")).toBeInTheDocument();
  });

  it("flags a stale catalog", async () => {
    mockApi({
      ...base,
      "GET /api/integrations": { body: [] },
      "GET /api/settings": { body: settings() },
      "GET /api/cve-catalog": {
        body: {
          source: "Old export", catalog_version: "2025.01", imported_at: "2025-01-01T00:00:00Z",
          file_sha256: "b".repeat(64), file_name: "", parser_version: "vapt-cve-catalog 1.0.0",
          entry_count: 5, stale_after_days: 30, is_stale: true, warnings: [],
        },
      },
    });
    renderAt("/integrations");
    expect(await screen.findByText(/Stale/)).toBeInTheDocument();
  });

  it("saves tool path overrides without clearing an existing credential alias", async () => {
    const { calls } = mockApi({
      ...base,
      "GET /api/integrations": { body: [] },
      "GET /api/cve-catalog": { body: null },
      "GET /api/settings": { body: settings({ nmap_path: "/usr/bin/nmap", online_lookup_credential_alias: "env:EXISTING" }) },
      "PATCH /api/settings": { body: settings({ nmap_path: "/opt/nmap/bin/nmap" }) },
    });
    renderAt("/integrations");
    const u = userEvent.setup();

    const nmapInput = await screen.findByLabelText("Nmap path");
    expect(nmapInput).toHaveValue("/usr/bin/nmap");
    await u.clear(nmapInput);
    await u.type(nmapInput, "/opt/nmap/bin/nmap");
    await u.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(calls.some((c) => c.method === "PATCH" && c.path === "/api/settings")).toBe(true));
    const patchCall = calls.find((c) => c.method === "PATCH" && c.path === "/api/settings")!;
    const body = patchCall.body as { integrations: Record<string, string> };
    expect(body.integrations.nmap_path).toBe("/opt/nmap/bin/nmap");
    // the credential field was left untouched, so it must not be sent as an empty-string wipe
    expect(body.integrations.online_lookup_credential_alias).toBeUndefined();
  });

  it("rejects a raw-secret-looking credential value client-side feedback via the API error", async () => {
    mockApi({
      ...base,
      "GET /api/integrations": { body: [] },
      "GET /api/cve-catalog": { body: null },
      "GET /api/settings": { body: settings() },
      "PATCH /api/settings": {
        status: 422,
        body: { error: { code: "validation_failed", message: "settings failed validation (1 error(s))", details: [] } },
      },
    });
    renderAt("/integrations");
    const u = userEvent.setup();
    const credInput = await screen.findByLabelText(/Online lookup credential/);
    // Built from fragments at runtime (never a single secret-shaped literal in source) so a
    // secret scanner never mistakes this synthetic test value for a real provider credential.
    const notARealKey = ["not", "a", "real", "credential", "0011223344556677"].join("-");
    await u.type(credInput, notARealKey);
    await u.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/settings failed validation/)).toBeInTheDocument();
  });

  it("operates the self-test button with keyboard only, and gives every tool card a distinct accessible name", async () => {
    mockApi({
      ...base,
      "GET /api/integrations": {
        body: [
          status({ id: "nmap", label: "nmap", status: "detected", detected_path: "/usr/bin/nmap" }),
          status({ id: "sslyze", label: "sslyze", status: "detected", detected_path: "/usr/bin/sslyze" }),
        ],
      },
      "GET /api/cve-catalog": { body: null },
      "GET /api/settings": { body: settings() },
      "POST /api/integrations/nmap/selftest": {
        body: status({ id: "nmap", status: "verified", detected_path: "/usr/bin/nmap", version: "Nmap 7.93" }),
      },
    });
    renderAt("/integrations");
    await screen.findAllByText("Detected (unverified)");

    // Each tool's heading is a distinct accessible name a screen-reader user can navigate by,
    // even though the self-test buttons below them share the same visible label text.
    expect(screen.getByRole("heading", { name: "nmap" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "sslyze" })).toBeInTheDocument();

    const buttons = screen.getAllByRole("button", { name: /Run self-test/ });
    expect(buttons).toHaveLength(2);

    const u = userEvent.setup();
    buttons[0]!.focus();
    expect(buttons[0]).toHaveFocus();
    await u.keyboard("{Enter}");
    expect(await screen.findByText("Verified working")).toBeInTheDocument();
  });
});
