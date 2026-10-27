// Standalone "Repository Scan" page (operator-requested): enter a repo + scan config in one
// page, no generic project wizard / network-scope step. Creates a scope-less repo_scan-only
// project behind the scenes, then starts the scan on it immediately.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "9".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
};

const projectRecord = overview({ name: "My repo scan", repository_path: "D:\\repo", scan_policy: { ...overview().project.scan_policy, allowed_modules: ["repo_scan"] } }).project;

const scanRecord = {
  scan_id: SID, project_id: PID, module: "repo_scan", profile: "default", state: "queued" as const,
  revision: 1, created_at: "", updated_at: "", queued_at: "", started_at: null, finished_at: null,
  targets: ["repo-scan"], authorized_targets: [], parameters: {},
  progress: { stage: "", percent: null, counters: {} }, cancel_requested: false,
  warnings: [], errors: [], output_refs: [], correlation_id: null, retry_of: null,
  final_reason: "", scope_hash: null,
};

describe("Repository Scan standalone page", () => {
  it("creates a scope-less project and starts the scan in one step", async () => {
    const { calls } = mockApi({
      ...base,
      "POST /api/projects": { status: 201, body: projectRecord },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: scanRecord },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: scanRecord, active: false, terminal: false, elapsed_seconds: null } },
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

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/api/projects")).toBe(true));
    const projectCall = calls.find((c) => c.method === "POST" && c.path === "/api/projects")!;
    const projectBody = projectCall.body as Record<string, unknown>;
    expect(projectBody.scope).toBeUndefined();
    expect(projectBody.scope_preview_hash).toBeUndefined();
    expect(projectBody.repository_path).toBe("D:\\repo");
    expect((projectBody.scan_policy as { allowed_modules: string[] }).allowed_modules).toEqual(["repo_scan"]);

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === `/api/projects/${PID}/scans`)).toBe(true));
    const scanCall = calls.find((c) => c.method === "POST" && c.path === `/api/projects/${PID}/scans`)!;
    expect((scanCall.body as { module: string }).module).toBe("repo_scan");
  });

  it("requires name, repository path and attestation before submitting", async () => {
    mockApi({ ...base });
    renderAt("/repo-scan");
    const u = userEvent.setup();

    await screen.findByText("Start a repository scan");
    await u.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("Name is required")).toBeInTheDocument();
    expect(screen.getByText("Repository path is required")).toBeInTheDocument();
    expect(screen.getByText("Organization is required")).toBeInTheDocument();
  });

  it("switches to URL mode and shows the credential-alias field", async () => {
    mockApi({ ...base });
    renderAt("/repo-scan");
    const u = userEvent.setup();

    await screen.findByText("Start a repository scan");
    await u.click(screen.getByRole("radio", { name: "Clone from a URL" }));
    expect(screen.getByRole("textbox", { name: /Repository URL/ })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /Credential alias/ })).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /Repository path/ })).not.toBeInTheDocument();
  });

  it("is reachable from the sidebar nav", async () => {
    mockApi({ ...base });
    renderAt("/repo-scan");
    await screen.findByText("Start a repository scan");
    const nav = screen.getByRole("navigation", { name: "Main navigation" });
    expect(within(nav).getByRole("link", { name: "Repository Scan" })).toBeInTheDocument();
  });
});
