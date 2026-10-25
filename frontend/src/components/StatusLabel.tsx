import { Badge } from "@mantine/core";
import type { AuthorizationStatus, IntegrationStatusValue, ScanState, Severity } from "../api/types";
import { humanize } from "../lib/format";

// Status is always conveyed by text (plus a shape symbol), never by colour alone.

const SEVERITY: Record<Severity, { color: string; symbol: string }> = {
  critical: { color: "red", symbol: "◆" },
  high: { color: "orange", symbol: "▲" },
  medium: { color: "yellow", symbol: "■" },
  low: { color: "blue", symbol: "●" },
  informational: { color: "gray", symbol: "○" },
};

export function SeverityLabel({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity];
  return (
    <Badge color={s.color} variant="light" leftSection={<span aria-hidden="true">{s.symbol}</span>}>
      {humanize(severity)}
    </Badge>
  );
}

const AUTH: Record<AuthorizationStatus, { color: string; label: string; symbol: string }> = {
  active: { color: "green", label: "Authorized", symbol: "✓" },
  expiring_soon: { color: "yellow", label: "Expiring soon", symbol: "!" },
  expired: { color: "red", label: "Authorization expired", symbol: "✕" },
  not_started: { color: "gray", label: "Not yet active", symbol: "…" },
  missing: { color: "gray", label: "No authorization", symbol: "–" },
};

export function AuthorizationLabel({ status }: { status: AuthorizationStatus }) {
  const a = AUTH[status];
  return (
    <Badge color={a.color} variant="light" leftSection={<span aria-hidden="true">{a.symbol}</span>}>
      {a.label}
    </Badge>
  );
}

const SCAN_COLORS: Partial<Record<ScanState, string>> = {
  completed: "green",
  completed_with_warnings: "yellow",
  failed: "red",
  blocked_scope: "red",
  expired_authorization: "red",
  running: "blue",
  queued: "blue",
  validating: "blue",
};

export function ScanStateLabel({ state }: { state: ScanState }) {
  return (
    <Badge color={SCAN_COLORS[state] ?? "gray"} variant="light">
      {humanize(state)}
    </Badge>
  );
}

export function ProjectStatusLabel({ status }: { status: "active" | "archived" }) {
  return (
    <Badge color={status === "active" ? "teal" : "gray"} variant="outline">
      {status === "active" ? "Active" : "Archived"}
    </Badge>
  );
}

const INTEGRATION_STATUS: Record<IntegrationStatusValue, { color: string; label: string; symbol: string }> = {
  not_configured: { color: "gray", label: "Not configured", symbol: "–" },
  not_found: { color: "red", label: "Configured path not found", symbol: "✕" },
  // Detected but never self-tested: deliberately not green — presence on PATH is not proof
  // the tool actually runs (acceptance criterion: no green success for an unverified tool).
  detected: { color: "blue", label: "Detected (unverified)", symbol: "?" },
  verified: { color: "green", label: "Verified working", symbol: "✓" },
  error: { color: "red", label: "Self-test failed", symbol: "✕" },
};

export function IntegrationStatusLabel({ status }: { status: IntegrationStatusValue }) {
  const s = INTEGRATION_STATUS[status];
  return (
    <Badge color={s.color} variant="light" leftSection={<span aria-hidden="true">{s.symbol}</span>}>
      {s.label}
    </Badge>
  );
}

export function NotConfiguredLabel({ children = "Not configured" }: { children?: string }) {
  // Deliberately neutral (never green) for anything not verified by the backend.
  return (
    <Badge color="gray" variant="outline" leftSection={<span aria-hidden="true">–</span>}>
      {children}
    </Badge>
  );
}
