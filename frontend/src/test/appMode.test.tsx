// VAPT Scan and Repository Scan are kept as two entirely separate feature areas (TBD-116):
// the app opens on a chooser, each mode's sidebar shows only that mode's pages, and a direct
// link/bookmark either infers a mode (when none is set yet) or is redirected back into the
// current mode (when one already is).
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { emptyPage, emptySummary, mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "4".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
  "GET /api/dashboard/summary": { body: emptySummary() },
  "GET /api/records/scans": { body: emptyPage() },
  "GET /api/projects": { body: emptyPage() },
};

beforeEach(() => {
  localStorage.clear();
});

describe("app mode separation", () => {
  it("shows the two-option chooser on first visit, with nothing else in the nav", async () => {
    mockApi({ ...base });
    renderAt("/");
    await screen.findByText("What do you want to do?");
    expect(screen.getByRole("button", { name: "VAPT Scan" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Repository Scan" })).toBeInTheDocument();
    // No mode chosen yet: the sidebar has no nav items at all.
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(nav).queryAllByRole("link")).toHaveLength(0);
  });

  it("choosing Repository Scan navigates there and shows only that nav item", async () => {
    mockApi({ ...base });
    renderAt("/");
    const u = userEvent.setup();
    await screen.findByText("What do you want to do?");
    await u.click(screen.getByRole("button", { name: "Repository Scan" }));

    await screen.findByText("Start a repository scan");
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    const links = within(nav).getAllByRole("link");
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAccessibleName("Repository Scan");
    expect(localStorage.getItem("kavach-app-mode")).toBe('"repo"');
  });

  it("choosing VAPT Scan navigates to the dashboard with the full nav minus Repository Scan", async () => {
    mockApi({ ...base });
    renderAt("/");
    const u = userEvent.setup();
    await screen.findByText("What do you want to do?");
    await u.click(screen.getByRole("button", { name: "VAPT Scan" }));

    await screen.findByText("Dashboard", { selector: "h1" });
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(nav).getByRole("link", { name: "Projects" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Repository Scan" })).not.toBeInTheDocument();
    expect(localStorage.getItem("kavach-app-mode")).toBe('"vapt"');
  });

  it("remembers the chosen mode across a later visit to '/'", async () => {
    localStorage.setItem("kavach-app-mode", JSON.stringify("repo"));
    mockApi({ ...base });
    renderAt("/");
    // Skips the chooser entirely and lands straight in the repo-scan flow.
    await screen.findByText("Start a repository scan");
    expect(screen.queryByText("What do you want to do?")).not.toBeInTheDocument();
  });

  it("a VAPT-only deep link is redirected to the chooser's home once Repository mode is active", async () => {
    localStorage.setItem("kavach-app-mode", JSON.stringify("repo"));
    mockApi({ ...base });
    renderAt("/projects");
    // Redirected away from /projects back to "/", which (mode=repo) sends it on to /repo-scan.
    await screen.findByText("Start a repository scan");
  });

  it("a Repository-Scan deep link is redirected home once VAPT mode is active", async () => {
    localStorage.setItem("kavach-app-mode", JSON.stringify("vapt"));
    mockApi({ ...base });
    renderAt("/repo-scan");
    await screen.findByText("Dashboard", { selector: "h1" });
  });

  it("'Switch mode' clears the stored mode and returns to the chooser", async () => {
    localStorage.setItem("kavach-app-mode", JSON.stringify("vapt"));
    mockApi({ ...base });
    renderAt("/");
    const u = userEvent.setup();
    await screen.findByText("Dashboard", { selector: "h1" });
    await u.click(screen.getByRole("button", { name: "Switch mode" }));
    await screen.findByText("What do you want to do?");
    expect(localStorage.getItem("kavach-app-mode")).toBe('""');
  });

  it("lets Repository Scan mode reach the scan-detail page after starting a scan, and still switch modes from there", async () => {
    // Regression: starting a repo scan navigates to /projects/:id/scans/:id (the shared
    // scan-detail page, where progress/findings/reports actually show), which is NOT
    // "/repo-scan" itself -- the guard used to bounce it straight back, so a started scan's
    // results were never reachable. A second regression: clicking "Switch mode" from any
    // page other than "/" used to silently undo itself, because the mode-inference effect
    // raced the router's own navigation back to "/" and re-inferred a mode from the still-
    // stale path before it updated.
    const projectRecord = overview({
      name: "My repo scan",
      repository_path: "D:\\repo",
      scan_policy: { ...overview().project.scan_policy, allowed_modules: ["repo_scan"] },
    }).project;
    const scanRecord = {
      scan_id: SID, project_id: PID, module: "repo_scan" as const, profile: "default", state: "queued" as const,
      revision: 1, created_at: "", updated_at: "", queued_at: "", started_at: null, finished_at: null,
      targets: ["repo-scan"], authorized_targets: [], parameters: {},
      progress: { stage: "", percent: null, counters: {} }, cancel_requested: false,
      warnings: [], errors: [], output_refs: [], correlation_id: null, retry_of: null,
      final_reason: "", scope_hash: null,
    };
    mockApi({
      ...base,
      "POST /api/projects": { status: 201, body: projectRecord },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: scanRecord },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: scanRecord, active: false, terminal: false, elapsed_seconds: null } },
      [`GET /api/projects/${PID}/scans/${SID}/events`]: { body: { items: [], offset: 0, limit: 200, has_more: false, corrupt_lines: 0 } },
      [`GET /api/projects/${PID}/scans/${SID}/console`]: { body: { lines: [] } },
    });
    renderAt("/repo-scan");
    const u = userEvent.setup();
    await screen.findByText("Start a repository scan");
    await u.type(screen.getByRole("textbox", { name: "Name" }), "My repo scan");
    await u.type(screen.getByRole("textbox", { name: /Repository path/ }), "D:\\repo");
    await u.type(screen.getByRole("textbox", { name: /Organization/ }), "Acme");
    await u.type(screen.getByRole("textbox", { name: /Target owner/ }), "Acme IT");
    await u.type(screen.getByRole("textbox", { name: /Authorized by/ }), "Jane");
    await u.click(screen.getByRole("checkbox", { name: /operator attestation/i }));
    await u.click(screen.getByRole("button", { name: "Start scan" }));

    // Lands on the scan-detail page, not bounced back to the start form.
    expect(await screen.findByText("Queued")).toBeInTheDocument();
    expect(screen.queryByText("Start a repository scan")).not.toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Switch mode" }));
    await screen.findByText("What do you want to do?");
  });

  it("filters repository-scan-only projects out of the VAPT Projects list", async () => {
    const vaptProject = overview({ name: "Web assessment" });
    const repoProject = overview(
      { name: "Repo-only scan", project_id: "prj_" + "c".repeat(32) },
      {},
    );
    repoProject.project.scan_policy = { ...repoProject.project.scan_policy, allowed_modules: ["repo_scan"] };
    localStorage.setItem("kavach-app-mode", JSON.stringify("vapt"));
    mockApi({
      ...base,
      "GET /api/projects": { body: { items: [vaptProject, repoProject], total: 2, offset: 0, limit: 20, errors: [] } },
    });
    renderAt("/projects");
    await screen.findByText("Web assessment");
    expect(screen.queryByText("Repo-only scan")).not.toBeInTheDocument();
  });
});
