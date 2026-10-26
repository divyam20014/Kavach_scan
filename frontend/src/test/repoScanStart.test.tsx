// Roadmap Phase 2 (TBD-088): the repo_scan start-dialog UI -- engine selection, the
// repository-path target placeholder, and a disabled start when no repository_path is set.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ScopePolicyView } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "7".repeat(32);

const base = {
  "GET /api/version": { body: VERSION },
  "GET /api/kill-switch": { body: { engaged: false, changed_at: null, reason: "", actor: "local-operator" } },
  "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
};

function policy(): ScopePolicyView {
  return {
    project_id: PID, scope: overview().project.scope, scope_hash: "a".repeat(64), valid: true,
    authorization: { decision_id: "d", at: "", allowed: true, reason: "allowed", message: "Authorization is active", check: "authorization", input: "", target: null, ip: null, rule: null, project_id: PID, scope_hash: null },
    can_start_active_work: true, internal_override: null, warnings: [], blocked_ranges: [],
  };
}

const scanRecord = {
  scan_id: SID, project_id: PID, module: "repo_scan", profile: "default", state: "queued" as const,
  revision: 1, created_at: "", updated_at: "", queued_at: "", started_at: null, finished_at: null,
  targets: ["repo-scan"], authorized_targets: [], parameters: {},
  progress: { stage: "", percent: null, counters: {} }, cancel_requested: false,
  warnings: [], errors: [], output_refs: [], correlation_id: null, retry_of: null,
  final_reason: "", scope_hash: null,
};

describe("Repository scan start dialog", () => {
  it("shows the configured repository path, selects engines, and sends them as parameters", async () => {
    const withRepoPath = overview({ repository_path: "/srv/some-repo" });
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: withRepoPath },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/jobs/modules": { body: [{ module: "repo_scan", label: "Repository scanner (Semgrep / Gitleaks / Trivy)", available: true, reason: "" }] },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: scanRecord },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: scanRecord, active: false, terminal: false, elapsed_seconds: null } },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Repository scanner/ }));

    expect(await within(card).findByText("/srv/some-repo")).toBeInTheDocument();
    await u.click(within(card).getByRole("checkbox", { name: /Gitleaks/ }));

    await u.click(within(card).getByRole("button", { name: /Review & confirm/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("/srv/some-repo")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("checkbox", { name: /I confirm/ }));
    await u.click(within(dialog).getByRole("button", { name: "Start job" }));

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/scans"))).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path.endsWith("/scans"))!.body as {
      module: string;
      targets: string[];
      parameters: { engines: string[] };
    };
    expect(body.module).toBe("repo_scan");
    expect(body.targets).toEqual(["repo-scan"]);
    expect(body.parameters.engines.sort()).toEqual(["gitleaks", "semgrep"]);
  });

  it("disables starting a repository scan when the project has no repository path", async () => {
    mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview({ repository_path: "" }) },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/jobs/modules": { body: [{ module: "repo_scan", label: "Repository scanner (Semgrep / Gitleaks / Trivy)", available: true, reason: "" }] },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Repository scanner/ }));

    expect(await within(card).findByText(/no repository path configured/i)).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: /Review & confirm/ })).toBeDisabled();
  });
});
