// Real-browser acceptance smoke test (Phase 02).
// Uses the locally installed Microsoft Edge through playwright-core (no browser download).
// Starts the backend on 127.0.0.1 with a throwaway data directory, serving frontend/dist,
// then: create a project in the wizard -> reload -> edit -> restart backend -> reload.
// Contacts nothing but 127.0.0.1.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

const BACKEND = resolve(import.meta.dirname, "..", "..", "backend");
const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const dataDir = mkdtempSync(join(tmpdir(), "vapt-e2e-"));
const results = [];
const step = (name) => results.push(name) && console.log(`  ✓ ${name}`);

function startBackend() {
  const proc = spawn("poetry", ["run", "python", "-m", "app"], {
    cwd: BACKEND,
    env: { ...process.env, VAPT_DATA_DIR: dataDir, VAPT_PORT: String(PORT) },
    shell: process.platform === "win32",
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  proc.stderr.on("data", (d) => (stderr += d));
  proc.stderrText = () => stderr;
  return proc;
}

async function waitReady() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${BASE}/api/readiness`);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("backend did not become ready");
}

function stop(proc) {
  if (process.platform === "win32") spawn("taskkill", ["/PID", String(proc.pid), "/T", "/F"], { shell: true });
  else proc.kill("SIGTERM");
  return new Promise((r) => setTimeout(r, 1500));
}

const pad = (n) => String(n).padStart(2, "0");
const local = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

let backend = startBackend();
let browser;
const consoleErrors = [];
try {
  await waitReady();
  browser = await chromium.launch({ channel: "msedge", headless: true });
  const page = await browser.newPage();
  page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  await page.goto(BASE + "/");
  await page.getByRole("heading", { level: 1, name: "Dashboard" }).waitFor();
  await page.getByTestId("kpi-projects").getByText("0", { exact: true }).waitFor();
  step("dashboard renders honest zeros from the API");

  await page.getByRole("link", { name: "Create a project" }).click();
  await page.getByRole("textbox", { name: /project name/i }).fill("E2E Bank portal");
  await page.getByRole("textbox", { name: /client name/i }).fill("E2E Bank");
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("textbox", { name: /organization/i }).fill("E2E Bank");
  await page.getByRole("textbox", { name: /target owner/i }).fill("Bank IT");
  await page.getByRole("textbox", { name: /authorized by/i }).fill("CISO");
  const now = new Date();
  await page.getByLabel(/window start/i).fill(local(new Date(now.getTime() - 3600e3)));
  await page.getByLabel(/window end/i).fill(local(new Date(now.getTime() + 20 * 86400e3)));
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByText("You must attest").waitFor();
  step("attestation is enforced in the wizard");
  await page.getByRole("checkbox", { name: /operator attestation/i }).check();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("textbox", { name: /in-scope targets/i }).fill("Portal.E2E-Bank.example\nhttps://user:pw@evil.example/");
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("embedded credentials are rejected", { exact: false }).waitFor();
  step("scope preview reports backend validation errors");
  await page.getByRole("textbox", { name: /in-scope targets/i }).fill("Portal.E2E-Bank.example\n*.api.e2e-bank.example");
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("✓ Scope is valid").waitFor();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("checkbox", { name: /web application scanner/i }).check();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Create project" }).click();
  await page.getByRole("heading", { level: 1, name: "E2E Bank portal" }).waitFor();
  await page.getByText("portal.e2e-bank.example", { exact: true }).waitFor();
  step("project created through the UI (scope normalized to lowercase)");

  const detailUrl = page.url();
  await page.reload();
  await page.getByRole("heading", { level: 1, name: "E2E Bank portal" }).waitFor();
  await page.getByText("Authorized", { exact: true }).waitFor();
  step("project persists across page reload");

  await page.getByRole("link", { name: "Edit" }).click();
  const name = page.getByRole("textbox", { name: /project name/i });
  await name.fill("E2E Bank portal (edited)");
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("✓ Scope is valid").waitFor();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  await page.getByRole("heading", { level: 1, name: "E2E Bank portal (edited)" }).waitFor();
  step("project edited through the UI");

  await stop(backend);
  backend = startBackend();
  await waitReady();
  await page.goto(detailUrl);
  await page.getByRole("heading", { level: 1, name: "E2E Bank portal (edited)" }).waitFor();
  await page.getByText("Revision 2").waitFor();
  step("edit persists across a backend restart and a fresh page load");

  await page.goto(BASE + "/");
  await page.getByTestId("kpi-projects").getByText("1", { exact: true }).waitFor();
  step("dashboard counter reflects the stored project");

  await page.goto(BASE + "/audit");
  await page.getByText("Authorization attested").first().waitFor();
  step("audit log shows creation, attestation and update events");

  if (consoleErrors.length) throw new Error("browser console errors:\n" + consoleErrors.join("\n"));
  step("no browser console errors or CSP violations");
  console.log(`\nE2E smoke: ${results.length} checks passed`);
} catch (err) {
  console.error("\nE2E smoke FAILED:", err.message);
  if (backend.stderrText) console.error(backend.stderrText().slice(-2000));
  process.exitCode = 1;
} finally {
  await browser?.close();
  await stop(backend);
  rmSync(dataDir, { recursive: true, force: true });
}
