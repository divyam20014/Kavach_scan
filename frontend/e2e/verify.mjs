// Phase 02 verification in a real browser (installed Microsoft Edge via playwright-core).
// Backend serves frontend/dist on 127.0.0.1 with a throwaway data dir; nothing else is contacted.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

const BACKEND = resolve(import.meta.dirname, "..", "..", "backend");
const PORT = 8798;
const BASE = `http://127.0.0.1:${PORT}`;
const dataDir = mkdtempSync(join(tmpdir(), "vapt-verify-"));
let passed = 0;
const ok = (msg) => {
  passed += 1;
  console.log(`  ✓ ${msg}`);
};
const assert = (cond, msg) => {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
};

function startBackend() {
  return spawn("poetry", ["run", "python", "-m", "app"], {
    cwd: BACKEND,
    env: { ...process.env, VAPT_DATA_DIR: dataDir, VAPT_PORT: String(PORT) },
    shell: process.platform === "win32",
    stdio: "ignore",
  });
}
async function waitReady() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${BASE}/api/readiness`)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("backend not ready");
}
async function stop(proc) {
  if (process.platform === "win32") spawn("taskkill", ["/PID", String(proc.pid), "/T", "/F"], { shell: true });
  else proc.kill("SIGTERM");
  for (let i = 0; i < 20; i++) {
    try {
      await fetch(`${BASE}/api/health`);
    } catch {
      return;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}
const api = async (method, path, body) => {
  const r = await fetch(BASE + path, { method, headers: { "Content-Type": "application/json" }, body: body && JSON.stringify(body) });
  return { status: r.status, json: await r.json() };
};
const day = 86400e3;
// Saving a scope requires the hash returned by /api/scope/preview for exactly that scope (Phase 03).
const previewed = async (targets) => {
  const { json } = await api("POST", "/api/scope/preview", { targets });
  if (!json.valid) throw new Error("preview failed: " + JSON.stringify(json.entries));
  return { scope: json.scope, scope_preview_hash: json.scope_hash };
};
const auth = (startOffset, endOffset) => ({
  organization: "Org", target_owner: "Owner", authorized_by: "CISO", reference: "R1",
  window_start: new Date(Date.now() + startOffset).toISOString(), window_end: new Date(Date.now() + endOffset).toISOString(),
  notes: "", attestation: true,
});

let backend = startBackend();
let browser;
const consoleErrors = [];
try {
  await waitReady();
  browser = await chromium.launch({ channel: "msedge", headless: true });
  const page = await browser.newPage();
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  page.on("console", (m) => {
    // Expected while the backend is deliberately offline in check 4.
    if (m.type() === "error" && !/ERR_CONNECTION_REFUSED|Failed to load resource/.test(m.text())) consoleErrors.push(m.text());
  });

  // 1. Empty state ------------------------------------------------------------------
  const emptyResp = page.waitForResponse((r) => r.url().endsWith("/api/dashboard/summary"));
  await page.goto(BASE + "/");
  const emptyJson = await (await emptyResp).json();
  assert(emptyJson.projects.total === 0 && emptyJson.findings.total === 0, "fresh data dir has zero records");
  await page.getByRole("heading", { name: "No projects yet" }).waitFor();
  await page.getByText(/No findings recorded/).waitFor();
  for (const id of ["kpi-projects", "kpi-scans", "kpi-findings", "kpi-assets"]) {
    assert((await page.getByTestId(id).locator("p").nth(1).textContent()) === "0", `${id} shows 0`);
  }
  ok("empty state: honest zeros and guidance, matching an empty API response");
  await page.goto(BASE + "/projects");
  await page.getByRole("heading", { name: "No projects yet" }).waitFor();
  await page.goto(BASE + "/findings");
  await page.getByRole("heading", { name: "No findings yet" }).waitFor();
  ok("empty states on projects and findings lists");

  // 2. KPIs come from the backend, not constants -------------------------------------
  const a = (await api("POST", "/api/projects", { name: "Alpha", client_name: "C1", authorization: auth(-day, 30 * day), ...(await previewed(["a.example.com"])) })).json;
  await api("POST", "/api/projects", { name: "Bravo", client_name: "C2", authorization: auth(-10 * day, -day), ...(await previewed(["b.example.com"])) });
  await api("POST", "/api/projects", { name: "Charlie", client_name: "C3", authorization: null, ...(await previewed(["c.example.com"])) });
  await api("PATCH", `/api/projects/${a.project_id}`, { expected_revision: 1, status: "archived" });
  const respPromise = page.waitForResponse((r) => r.url().endsWith("/api/dashboard/summary"));
  await page.goto(BASE + "/");
  const summary = await (await respPromise).json();
  const kpis = {
    "kpi-projects": summary.projects.total,
    "kpi-scans": summary.scans.total,
    "kpi-active-scans": summary.scans.active,
    "kpi-failed-scans": summary.scans.failed,
    "kpi-findings": summary.findings.total,
    "kpi-confirmed": summary.findings.by_confidence.confirmed,
    "kpi-retest": summary.findings.by_status.retest_needed,
    "kpi-assets": summary.assets.total,
  };
  for (const [id, expected] of Object.entries(kpis)) {
    const shown = await page.getByTestId(id).locator("p").nth(1).textContent();
    assert(shown === String(expected), `${id}: screen ${shown} vs network ${expected}`);
  }
  assert(summary.projects.total === 3 && summary.projects.archived === 1, "network summary reflects seeded projects");
  await page.getByText(/1 project\(s\) have an expired authorization window/).waitFor();
  await page.getByText(/1 project\(s\) have no authorization record/).waitFor();
  ok(`all 8 KPI values on screen equal the captured /api/dashboard/summary response (projects=${summary.projects.total})`);

  await page.route("**/api/dashboard/summary", async (route) => {
    const real = await route.fetch();
    const body = await real.json();
    body.projects.total = 4242;
    body.findings.total = 777;
    body.assets.total = 31337;
    await route.fulfill({ response: real, json: body });
  });
  await page.reload();
  await page.getByTestId("kpi-projects").getByText("4242", { exact: true }).waitFor();
  assert((await page.getByTestId("kpi-findings").locator("p").nth(1).textContent()) === "777", "findings follows response");
  assert((await page.getByTestId("kpi-assets").locator("p").nth(1).textContent()) === "31337", "assets follows response");
  await page.unroute("**/api/dashboard/summary");
  ok("tampering with the network response changes the rendered KPIs (no constants in rendering)");

  // 3. Create / edit survive reload (UI) ---------------------------------------------
  await page.goto(BASE + "/projects/new");
  await page.getByRole("textbox", { name: /project name/i }).fill("UI created");
  await page.getByRole("textbox", { name: /client name/i }).fill("UI client");
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("checkbox", { name: /record an authorization now/i }).uncheck();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("textbox", { name: /in-scope targets/i }).fill("ui.example.com");
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("✓ Scope is valid").waitFor();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Create project" }).click();
  await page.getByRole("heading", { level: 1, name: "UI created" }).waitFor();
  const uiUrl = page.url();
  await page.reload();
  await page.getByRole("heading", { level: 1, name: "UI created" }).waitFor();
  await page.getByText("No authorization", { exact: true }).waitFor();
  await page.getByRole("link", { name: "Edit" }).click();
  await page.getByRole("textbox", { name: /project name/i }).fill("UI edited");
  for (let i = 0; i < 2; i++) await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("✓ Scope is valid").waitFor();
  for (let i = 0; i < 2; i++) await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  await page.getByRole("heading", { level: 1, name: "UI edited" }).waitFor();
  await page.goto(uiUrl);
  await page.getByRole("heading", { level: 1, name: "UI edited" }).waitFor();
  await page.getByText("Revision 2").waitFor();
  ok("project created and edited in the UI survive a full reload");

  // 4. Backend offline ---------------------------------------------------------------
  await page.goto(BASE + "/");
  await page.getByRole("heading", { level: 1, name: "Dashboard" }).waitFor();
  await stop(backend);
  await page.getByRole("navigation", { name: /main navigation/i }).getByRole("link", { name: "Projects" }).click();
  const offline = page.getByRole("alert").filter({ hasText: "Cannot reach the Workbench backend" });
  await offline.waitFor({ timeout: 15000 });
  ok("backend offline: clear 'cannot reach backend' alert with retry (no fake data shown)");
  backend = startBackend();
  await waitReady();
  await offline.getByRole("button", { name: "Retry" }).click();
  await page.getByRole("link", { name: "UI edited" }).waitFor();
  ok("retry after the backend returns loads real data");

  // 5. Validation errors from the backend ------------------------------------------
  await page.goto(BASE + "/projects/new");
  await page.getByRole("textbox", { name: /project name/i }).fill("Bad labels");
  await page.getByRole("textbox", { name: /client name/i }).fill("Client");
  await page.getByRole("textbox", { name: /labels/i }).fill("ok, <script>");
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("checkbox", { name: /record an authorization now/i }).uncheck();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("textbox", { name: /in-scope targets/i }).fill("bad.example.com");
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("✓ Scope is valid").waitFor();
  for (let i = 0; i < 2; i++) await page.getByRole("button", { name: "Next" }).click();
  const createResp = page.waitForResponse((r) => r.url().endsWith("/api/projects") && r.request().method() === "POST");
  await page.getByRole("button", { name: "Create project" }).click();
  assert((await createResp).status() === 422, "backend rejected the invalid label with 422");
  const alert = page.getByRole("alert").filter({ hasText: "Could not save the project" });
  await alert.waitFor();
  const alertText = await alert.textContent();
  assert(/labels › 1: String should match pattern/.test(alertText), `useful field message, got: ${alertText}`);
  assert(!/<script>/.test(await page.locator("body").innerHTML()) || !(await page.locator("script:not([src])").count()), "no injected script element");
  ok(`backend validation error shown with field path: "${alertText.match(/labels › 1: [^.;]*/)[0]}"`);

  const proj = (await api("GET", "/api/projects?q=UI%20edited")).json.items[0].project;
  await page.goto(`${BASE}/projects/${proj.project_id}/edit`);
  await page.getByRole("textbox", { name: /project name/i }).fill("Stale tab edit");
  await api("PATCH", `/api/projects/${proj.project_id}`, { expected_revision: proj.revision, notes: "changed elsewhere" });
  for (let i = 0; i < 2; i++) await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("✓ Scope is valid").waitFor();
  for (let i = 0; i < 2; i++) await page.getByRole("button", { name: "Next" }).click();
  await page.getByRole("button", { name: "Save changes" }).click();
  await page.getByRole("alert").filter({ hasText: /Record was modified/ }).waitFor();
  assert((await api("GET", `/api/projects/${proj.project_id}`)).json.project.name === "UI edited", "stale edit did not overwrite");
  ok("concurrent edit: stale save is refused with a clear conflict message; no lost update");

  // 6. Deletion confirmation -----------------------------------------------------------
  await page.goto(`${BASE}/projects/${proj.project_id}`);
  await page.getByRole("button", { name: "Delete…" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText(/Finding record\(s\)/).waitFor();
  const del = dialog.getByRole("button", { name: "Delete project" });
  assert(await del.isDisabled(), "delete disabled before typing");
  await dialog.getByRole("textbox").fill("ui edited");
  assert(await del.isDisabled(), "delete disabled for wrong-case name");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  assert((await api("GET", `/api/projects/${proj.project_id}`)).status === 200, "cancel keeps the project");
  await page.getByRole("button", { name: "Delete…" }).click();
  await dialog.getByRole("textbox").fill("UI edited");
  await dialog.getByRole("button", { name: "Delete project" }).click();
  await page.getByRole("heading", { level: 1, name: "Projects" }).waitFor();
  assert((await api("GET", `/api/projects/${proj.project_id}`)).status === 404, "project removed on the backend");
  const audit = (await api("GET", `/api/audit?project_id=${proj.project_id}&action=project_deleted`)).json;
  assert(audit.items.length === 1, "deletion audited");
  ok("delete: impact shown, disabled until exact name, cancel is safe, confirm deletes + audits");

  // 7. Keyboard navigation -------------------------------------------------------------
  await page.goto(BASE + "/");
  await page.getByRole("heading", { level: 1, name: "Dashboard" }).waitFor();
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  assert(await skip.evaluate((el) => el === document.activeElement), "first Tab focuses skip link");
  const box = await skip.boundingBox();
  assert(box && box.y >= 0, "skip link becomes visible on focus");
  await page.keyboard.press("Enter");
  assert(await page.evaluate(() => document.activeElement?.id === "main"), "skip link moves focus to main");
  await page.goto(BASE + "/");
  await page.getByRole("heading", { level: 1, name: "Dashboard" }).waitFor();
  let onProjects = false;
  for (let i = 0; i < 30 && !onProjects; i++) {
    await page.keyboard.press("Tab");
    onProjects = await page.evaluate(() => document.activeElement?.tagName === "A" && document.activeElement.textContent === "Projects");
  }
  assert(onProjects, "Projects nav link reachable by Tab");
  const outline = await page.evaluate(() => getComputedStyle(document.activeElement).outlineStyle);
  assert(outline !== "none", `visible focus indicator (outline-style=${outline})`);
  await page.keyboard.press("Enter");
  await page.getByRole("heading", { level: 1, name: "Projects" }).waitFor();
  let onNew = false;
  for (let i = 0; i < 40 && !onNew; i++) {
    await page.keyboard.press("Tab");
    onNew = await page.evaluate(() => document.activeElement?.textContent === "New project");
  }
  assert(onNew, "New project reachable by Tab");
  await page.keyboard.press("Enter");
  await page.getByRole("textbox", { name: /project name/i }).waitFor();
  await page.getByRole("textbox", { name: /project name/i }).focus();
  await page.keyboard.type("Keyboard only");
  await page.keyboard.press("Tab");
  await page.keyboard.type("Keyboard client");
  await page.keyboard.press("Enter");
  await page.getByRole("checkbox", { name: /operator attestation/i }).focus();
  await page.keyboard.press("Space");
  assert(await page.getByRole("checkbox", { name: /operator attestation/i }).isChecked(), "Space toggles attestation");
  ok("keyboard: skip link, Tab to nav with visible focus ring, Enter activates, wizard operable without a mouse");


  // 8. Phase 03: scope policy card and dry-run checker on a real project --------------------
  const scoped = (await api("POST", "/api/projects", { name: "Scoped", client_name: "C", authorization: auth(-day, 10 * day), ...(await previewed(["app.example.com"])) })).json;
  await page.goto(`${BASE}/projects/${scoped.project_id}`);
  const card = page.getByRole("region", { name: /scope policy/i });
  await card.getByText("Active work permitted").waitFor();
  const urlBox = card.getByRole("textbox", { name: "URL" });
  const checkOnce = async (url, ips = "") => {
    await urlBox.fill(url);
    await card.getByRole("textbox", { name: /simulated resolved ips/i }).fill(ips);
    const resp = page.waitForResponse((r) => r.url().endsWith("/scope/check"));
    await card.getByRole("button", { name: "Check" }).click();
    return (await (await resp).json()).allowed;
  };
  assert((await checkOnce("https://app.example.com.evil.test/")) === false, "suffix-confusion host blocked");
  await card.getByText("✕ Would be blocked").waitFor();
  assert((await checkOnce("https://app.example.com/", "169.254.169.254")) === false, "metadata IP blocked");
  await card.getByText(/cloud metadata address/).waitFor();
  assert((await checkOnce("https://app.example.com/login", "93.184.216.34")) === true, "in-scope URL allowed");
  await card.getByText("✓ Would be allowed").waitFor();
  ok("scope policy card: gate status, suffix-confusion and metadata blocked, in-scope allowed (dry run)");

  if (consoleErrors.length) throw new Error("console errors:\n" + consoleErrors.join("\n"));
  ok("no unexpected browser console errors or CSP violations");
  console.log(`\nPhase 02 browser verification: ${passed} checks passed`);
} catch (err) {
  console.error("\nVERIFICATION FAILED:", err.message);
  process.exitCode = 1;
} finally {
  await browser?.close();
  await stop(backend);
  rmSync(dataDir, { recursive: true, force: true });
}
