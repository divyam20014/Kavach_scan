import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ScopePreviewResponse } from "../api/types";
import { validateStep, type WizardValues } from "../pages/ProjectWizardPage";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const VALID_PREVIEW: ScopePreviewResponse = {
  valid: true,
  scope: overview().project.scope,
  entries: [{ field: "targets", input: "app.example.com", kind: "hostname", normalized: "app.example.com", error: null, warnings: [] }],
  error_count: 0,
  notes: ["Preview only: enforcement in Phase 03."],
};

function apiFor(overrides: Record<string, unknown> = {}) {
  return mockApi({
    "GET /api/version": { body: VERSION },
    "POST /api/scope/preview": { body: VALID_PREVIEW },
    "POST /api/projects": { status: 201, body: overview().project },
    [`GET /api/projects/${PID}`]: { body: overview() },
    "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
    ...(overrides as Record<string, { body: unknown }>),
  });
}

const user = () => userEvent.setup();

async function fillProjectStep(u: ReturnType<typeof user>) {
  await u.type(await screen.findByRole("textbox", { name: /project name/i }), "Web assessment");
  await u.type(screen.getByRole("textbox", { name: /client name/i }), "Acme Corp");
  await u.click(screen.getByRole("button", { name: "Next" }));
}

async function fillAuthorizationStep(u: ReturnType<typeof user>) {
  await u.type(await screen.findByRole("textbox", { name: /organization/i }), "Acme Corp");
  await u.type(screen.getByRole("textbox", { name: /target owner/i }), "Acme IT");
  await u.type(screen.getByRole("textbox", { name: /authorized by/i }), "CISO");
  await u.type(screen.getByLabelText(/window start/i), "2026-10-01T09:00");
  await u.type(screen.getByLabelText(/window end/i), "2026-12-01T18:00");
  await u.click(screen.getByRole("checkbox", { name: /operator attestation/i }));
  await u.click(screen.getByRole("button", { name: "Next" }));
}

describe("project wizard validation", () => {
  it("unit: validates required fields and window order", () => {
    const base = { name: "", client_name: "", includeAuthorization: true, attestation: false, window_start: "2026-10-02T00:00", window_end: "2026-10-01T00:00" } as WizardValues;
    expect(validateStep(0, base)).toMatchObject({ name: expect.any(String), client_name: expect.any(String) });
    const auth = validateStep(1, { ...base, organization: "", target_owner: "", authorized_by: "" });
    expect(auth.window_end).toMatch(/after start/);
    expect(auth.attestation).toMatch(/attest/);
    expect(validateStep(1, { ...base, includeAuthorization: false })).toEqual({});
  });

  it("shows inline errors with accessible labels on the first step", async () => {
    apiFor();
    const u = user();
    renderAt("/projects/new");
    await u.click(await screen.findByRole("button", { name: "Next" }));
    expect(await screen.findByText("Project name is required")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /project name/i })).toHaveAttribute("aria-invalid", "true");
  });

  it("requires operator attestation before leaving the authorization step", async () => {
    apiFor();
    const u = user();
    renderAt("/projects/new");
    await fillProjectStep(u);
    await u.click(await screen.findByRole("button", { name: "Next" }));
    expect(await screen.findByText(/must attest/)).toBeInTheDocument();
    expect(screen.getByText(/not legal verification/)).toBeInTheDocument();
  });

  it("blocks the scope step until a valid preview exists and shows preview errors", async () => {
    const bad: ScopePreviewResponse = {
      valid: false,
      scope: null,
      entries: [{ field: "targets", input: "https://u:p@x.com", kind: "invalid", normalized: null, error: "URLs with embedded credentials are rejected", warnings: [] }],
      error_count: 1,
      notes: [],
    };
    apiFor({ "POST /api/scope/preview": { body: bad } });
    const u = user();
    renderAt("/projects/new");
    await fillProjectStep(u);
    await fillAuthorizationStep(u);
    await u.type(await screen.findByRole("textbox", { name: /in-scope targets/i }), "https://u:p@x.com");
    await u.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText(/Preview the scope/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Preview scope" }));
    expect(await screen.findByText(/embedded credentials are rejected/)).toBeInTheDocument();
    expect(screen.getByText(/1 problem/)).toBeInTheDocument();
  });
});

describe("project wizard submission", () => {
  it("creates a project with the normalized scope and attested authorization", async () => {
    const { calls } = apiFor();
    const u = user();
    renderAt("/projects/new");
    await fillProjectStep(u);
    await fillAuthorizationStep(u);
    await u.type(await screen.findByRole("textbox", { name: /in-scope targets/i }), "App.Example.com");
    await u.click(screen.getByRole("button", { name: "Preview scope" }));
    expect(await screen.findByText("✓ Scope is valid")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("checkbox", { name: /web application scanner/i }));
    await u.click(screen.getByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("button", { name: "Create project" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/api/projects")).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.path === "/api/projects")!.body as {
      name: string;
      scope: { hosts: string[] };
      authorization: { attestation: boolean; window_start: string };
      scan_policy: { allowed_modules: string[] };
    };
    expect(body.name).toBe("Web assessment");
    expect(body.scope.hosts).toEqual(["app.example.com"]); // from the preview, not the raw text
    expect(body.authorization.attestation).toBe(true);
    expect(body.authorization.window_start).toMatch(/Z$/); // sent with timezone
    expect(body.scan_policy.allowed_modules).toEqual(["web_app"]);
    expect(calls.find((c) => c.path === "/api/scope/preview")!.body).toMatchObject({ targets: ["App.Example.com"] });
  });

  it("shows backend validation errors in a useful way", async () => {
    apiFor({
      "POST /api/projects": {
        status: 422,
        body: {
          error: {
            code: "validation_failed",
            message: "Request validation failed.",
            correlation_id: "corr-1",
            details: [{ loc: ["body", "scan_policy", "max_concurrency"], message: "Input should be less than or equal to 8", type: "less_than_equal" }],
          },
        },
      },
    });
    const u = user();
    renderAt("/projects/new");
    await fillProjectStep(u);
    await fillAuthorizationStep(u);
    await u.type(await screen.findByRole("textbox", { name: /in-scope targets/i }), "app.example.com");
    await u.click(screen.getByRole("button", { name: "Preview scope" }));
    await screen.findByText("✓ Scope is valid");
    await u.click(screen.getByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("button", { name: "Create project" }));
    const title = await screen.findByText("Could not save the project");
    const alert = title.closest('[role="alert"]') as HTMLElement;
    expect(alert).not.toBeNull();
    expect(alert).toHaveTextContent("scan_policy › max_concurrency: Input should be less than or equal to 8");
    expect(alert).toHaveTextContent("Reference: corr-1");
  });

  it("edits an existing project with optimistic-concurrency revision", async () => {
    const { calls } = apiFor({ [`PATCH /api/projects/${PID}`]: { body: overview({ name: "Renamed", revision: 2 }).project } });
    const u = user();
    renderAt(`/projects/${PID}/edit`);
    const name = await screen.findByRole("textbox", { name: /project name/i });
    expect(name).toHaveValue("Web assessment");
    await u.clear(name);
    await u.type(name, "Renamed");
    await u.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText(/stored authorization is kept/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("button", { name: "Preview scope" }));
    await screen.findByText("✓ Scope is valid");
    await u.click(screen.getByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("button", { name: "Next" }));
    await u.click(await screen.findByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const body = calls.find((c) => c.method === "PATCH")!.body as Record<string, unknown>;
    expect(body.expected_revision).toBe(1);
    expect(body.name).toBe("Renamed");
    expect(body).not.toHaveProperty("authorization"); // untouched authorization is not re-attested
  });
});
