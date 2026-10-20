// Phase 02 verification: keyboard operation and source hygiene.
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { emptyPage, emptySummary, mockApi, renderAt, VERSION } from "./utils";

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/dashboard/summary": { body: emptySummary() },
  "GET /api/projects": { body: emptyPage() },
  "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
};

describe("keyboard navigation", () => {
  it("offers a skip link as the first Tab stop that moves focus to main content", async () => {
    mockApi(base);
    renderAt("/");
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    const u = userEvent.setup();
    await u.tab();
    const skip = screen.getByRole("link", { name: "Skip to main content" });
    expect(skip).toHaveFocus();
    await u.keyboard("{Enter}");
    expect(document.getElementById("main")).toHaveFocus();
  });

  it("reaches and activates navigation links with Tab and Enter only", async () => {
    mockApi(base);
    renderAt("/");
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    const u = userEvent.setup();
    let reached = false;
    for (let i = 0; i < 25 && !reached; i++) {
      await u.tab();
      reached = document.activeElement?.textContent === "Projects" && document.activeElement.tagName === "A";
    }
    expect(reached).toBe(true);
    await u.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { level: 1, name: "Projects" })).toBeInTheDocument();
  });

  it("submits a wizard step with Enter and toggles attestation with Space", async () => {
    mockApi(base);
    renderAt("/projects/new");
    const u = userEvent.setup();
    await u.click(await screen.findByRole("textbox", { name: /project name/i }));
    await u.keyboard("Kbd project");
    await u.tab();
    await u.keyboard("Kbd client{Enter}");
    const attest = await screen.findByRole("checkbox", { name: /operator attestation/i });
    attest.focus();
    await u.keyboard(" ");
    expect(attest).toBeChecked();
  });
});

describe("source hygiene", () => {
  const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) {
        if (name !== "test") walk(full);
      } else if (/\.(ts|tsx)$/.test(name)) files.push(full);
    }
  };
  walk(SRC);

  it("ships no sample, fake or randomly generated data in production code", () => {
    expect(files.length).toBeGreaterThan(10);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/lorem|ipsum|dummy|faker|Math\.random|mockData|sampleData/i);
    }
  });

  it("binds every dashboard KPI value to the API response", () => {
    const dashboard = readFileSync(join(SRC, "pages", "DashboardPage.tsx"), "utf8");
    const values = [...dashboard.matchAll(/<KpiCard[\s\S]*?value=\{([^}]+)\}/g)].map((m) => m[1]!.trim());
    expect(values.length).toBe(8);
    for (const v of values) expect(v).toMatch(/^(projects|scans|findings|assets)\./);
  });

  it("never renders raw HTML", () => {
    for (const file of files) expect(readFileSync(file, "utf8"), file).not.toMatch(/dangerouslySetInnerHTML|innerHTML\s*=/);
  });
});

describe("untrusted content rendering", () => {
  it("renders hostile project names and audit metadata as inert text", async () => {
    const { overview } = await import("./utils");
    const evil = '<img src=x onerror="window.__pwned=1">';
    const item = overview({ name: evil, client_name: "<script>alert(1)</script>" });
    mockApi({
      ...base,
      "GET /api/projects": { body: { ...emptyPage(), items: [item], total: 1 } },
    });
    renderAt("/projects");
    expect(await screen.findByText(evil)).toBeInTheDocument();
    expect(document.querySelector("img[src='x']")).toBeNull();
    expect(document.querySelectorAll("script").length).toBe(0);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});
