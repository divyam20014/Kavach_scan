// VAPT Scan and Repository Scan are kept as two entirely separate feature areas (TBD-116):
// the app opens on a chooser, each mode's sidebar shows only that mode's pages, and a direct
// link/bookmark either infers a mode (when none is set yet) or is redirected back into the
// current mode (when one already is).
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { emptyPage, emptySummary, mockApi, overview, renderAt, VERSION } from "./utils";

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
