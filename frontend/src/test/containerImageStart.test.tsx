// Security/reliability/scope roadmap Phase 3 (TBD-110): the container_image start-dialog
// UI -- image reference entry, no target-list requirement, and a disabled start until an
// image reference is entered.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ScopePolicyView } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const SID = "scn_" + "8".repeat(32);

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
  scan_id: SID, project_id: PID, module: "container_image", profile: "default", state: "queued" as const,
  revision: 1, created_at: "", updated_at: "", queued_at: "", started_at: null, finished_at: null,
  targets: ["container-image-scan"], authorized_targets: [], parameters: {},
  progress: { stage: "", percent: null, counters: {} }, cancel_requested: false,
  warnings: [], errors: [], output_refs: [], correlation_id: null, retry_of: null,
  final_reason: "", scope_hash: null,
};

describe("Container image scan start dialog", () => {
  it("sends the entered image reference as a parameter and a placeholder target", async () => {
    const { calls } = mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/jobs/modules": { body: [{ module: "container_image", label: "Container image scanner (Trivy)", available: true, reason: "" }] },
      [`POST /api/projects/${PID}/scans`]: { status: 202, body: scanRecord },
      [`GET /api/projects/${PID}/scans/${SID}`]: { body: { scan: scanRecord, active: false, terminal: false, elapsed_seconds: null } },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Container image scanner/ }));

    expect(within(card).getByRole("button", { name: /Review & confirm/ })).toBeDisabled();
    await u.type(within(card).getByRole("textbox", { name: /Image reference/ }), "myapp:1.2.3");
    expect(within(card).getByRole("button", { name: /Review & confirm/ })).not.toBeDisabled();

    await u.click(within(card).getByRole("button", { name: /Review & confirm/ }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("myapp:1.2.3")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("checkbox", { name: /I confirm/ }));
    await u.click(within(dialog).getByRole("button", { name: "Start job" }));

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/scans"))).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path.endsWith("/scans"))!.body as {
      module: string;
      targets: string[];
      parameters: { image: string };
    };
    expect(body.module).toBe("container_image");
    expect(body.targets).toEqual(["container-image-scan"]);
    expect(body.parameters.image).toBe("myapp:1.2.3");
  });

  it("does not require a target list to be entered", async () => {
    mockApi({
      ...base,
      [`GET /api/projects/${PID}`]: { body: overview() },
      [`GET /api/projects/${PID}/scope/policy`]: { body: policy() },
      "GET /api/jobs/modules": { body: [{ module: "container_image", label: "Container image scanner (Trivy)", available: true, reason: "" }] },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    const card = await screen.findByRole("region", { name: "Start a job" });
    await u.click(await within(card).findByRole("radio", { name: /Container image scanner/ }));

    expect(within(card).getByText(/no target list is needed/i)).toBeInTheDocument();
    expect(within(card).queryByRole("textbox", { name: /targets/i })).not.toBeInTheDocument();
  });
});
