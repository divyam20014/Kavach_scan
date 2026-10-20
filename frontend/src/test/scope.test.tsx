// Phase 03 UI: scope policy card, dry-run URL check, internal-target override.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { Decision, ScopeCheckResponse, ScopePolicyView } from "../api/types";
import { mockApi, overview, PID, renderAt, VERSION } from "./utils";

const decision = (over: Partial<Decision>): Decision => ({
  decision_id: Math.random().toString(16).slice(2),
  at: "2026-11-01T00:00:00Z",
  allowed: true,
  reason: "allowed",
  message: "ok",
  check: "target",
  input: "",
  target: null,
  ip: null,
  rule: null,
  project_id: PID,
  scope_hash: "a".repeat(64),
  ...over,
});

function policyView(over: Partial<ScopePolicyView> = {}): ScopePolicyView {
  return {
    project_id: PID,
    scope: overview().project.scope,
    scope_hash: "a".repeat(64),
    valid: true,
    authorization: decision({ check: "authorization", message: "Authorization is active" }),
    can_start_active_work: true,
    internal_override: null,
    warnings: [],
    blocked_ranges: [
      { network: "10.0.0.0/8", category: "private", label: "RFC 1918 private", overridable: true },
      { network: "169.254.169.254/32", category: "cloud_metadata", label: "Instance metadata", overridable: false },
    ],
    ...over,
  };
}

function apiWith(policy: ScopePolicyView, extra: Record<string, unknown> = {}) {
  return mockApi({
    "GET /api/version": { body: VERSION },
    [`GET /api/projects/${PID}`]: { body: overview() },
    [`GET /api/projects/${PID}/scope/policy`]: { body: policy },
    "GET /api/audit": { body: { items: [], offset: 0, limit: 10, has_more: false, corrupt_lines: 0 } },
    ...(extra as Record<string, { body: unknown }>),
  });
}

describe("scope policy card", () => {
  it("shows that active work is blocked, with the reason as text", async () => {
    apiWith(policyView({
      can_start_active_work: false,
      authorization: decision({ allowed: false, reason: "authorization_expired", check: "authorization", message: "Authorization window ended 2026-10-01" }),
      warnings: ["In-scope range 10.0.0.0/24 overlaps 10.0.0.0/8 (RFC 1918 private); it is blocked unless an internal-target override covers it."],
    }));
    renderAt(`/projects/${PID}`);
    const card = await screen.findByRole("region", { name: /scope policy/i });
    expect(await within(card).findByText("Active work blocked")).toBeInTheDocument();
    expect(within(card).getByText(/Authorization window ended/)).toBeInTheDocument();
    expect(within(card).getByText(/overlaps 10.0.0.0\/8/)).toBeInTheDocument();
  });

  it("lists blocked ranges and marks metadata as never overridable", async () => {
    apiWith(policyView());
    renderAt(`/projects/${PID}`);
    const table = await screen.findByRole("table", { name: /default-blocked address ranges/i });
    expect(within(table).getByText("169.254.169.254/32").closest("tr")).toHaveTextContent("✕ Never");
    expect(within(table).getByText("10.0.0.0/8").closest("tr")).toHaveTextContent("Yes (audited, time-limited)");
  });

  it("runs a dry-run URL check and shows every decision with its rule", async () => {
    const result: ScopeCheckResponse = {
      allowed: false,
      summary: "Would be blocked",
      authorization: decision({ check: "authorization", message: "Authorization is active" }),
      target: decision({ check: "target", message: "target in scope", rule: "host app.example.com; path /" }),
      resolved_ips: [decision({ allowed: false, reason: "ip_blocked_range", check: "resolved_ip", message: "127.0.0.1 is in a blocked range (Loopback)", rule: "blocked 127.0.0.0/8" })],
      dns_note: null,
    };
    const { calls } = apiWith(policyView(), { [`POST /api/projects/${PID}/scope/check`]: { body: result } });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    await u.type(await screen.findByRole("textbox", { name: "URL" }), "https://app.example.com/");
    await u.type(screen.getByRole("textbox", { name: /simulated resolved ips/i }), "127.0.0.1");
    await u.click(screen.getByRole("button", { name: "Check" }));
    expect(await screen.findByText("✕ Would be blocked")).toBeInTheDocument();
    expect(screen.getByText(/127.0.0.1 is in a blocked range/)).toBeInTheDocument();
    expect(screen.getByText(/rule: blocked 127.0.0.0\/8/)).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith("/scope/check"))!.body).toEqual({ url: "https://app.example.com/", resolved_ips: ["127.0.0.1"] });
  });

  it("adds an override only with attestation and shows backend rejections", async () => {
    const { calls } = apiWith(policyView(), {
      [`PUT /api/projects/${PID}/internal-override`]: {
        status: 422,
        body: { error: { code: "validation_failed", message: "Request validation failed.", details: [{ loc: ["body"], message: "Value error, 10.0.0.0/8 is too broad; use /16 or narrower", type: "value_error" }] } },
      },
    });
    renderAt(`/projects/${PID}`);
    const u = userEvent.setup();
    await u.click(await screen.findByRole("button", { name: "Add override…" }));
    await u.type(screen.getByRole("textbox", { name: /blocked ranges to allow/i }), "10.0.0.0/8");
    await u.type(screen.getByRole("textbox", { name: /^reason/i }), "internal staging network");
    await u.type(screen.getByLabelText(/expires/i), "2026-11-05T10:00");
    await u.click(screen.getByRole("checkbox", { name: /operator attestation/i }));
    await u.click(screen.getByRole("button", { name: "Save override" }));
    expect(await screen.findByText(/too broad; use \/16 or narrower/)).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toMatchObject({ expected_revision: 1, ip_ranges: ["10.0.0.0/8"], attestation: true });
    expect((put.body as { expires_at: string }).expires_at).toMatch(/Z$/);
  });

  it("shows an active override and removes it with the current revision", async () => {
    const { calls } = apiWith(
      policyView({
        internal_override: {
          active: true,
          override: { ip_ranges: ["10.20.0.0/24"], reason: "internal staging network", expires_at: "2026-11-08T00:00:00Z", audit_event_id: "evt_" + "c".repeat(32) },
        },
      }),
      { [`DELETE /api/projects/${PID}/internal-override`]: { body: overview().project } },
    );
    renderAt(`/projects/${PID}`);
    expect(await screen.findByText("Internal-target override active")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove override" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
    expect(calls.find((c) => c.method === "DELETE")!.query.get("expected_revision")).toBe("1");
  });
});
