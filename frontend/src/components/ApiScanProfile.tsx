import { Alert, Group, Select, Stack, Switch, Text } from "@mantine/core";
import { useApiSpecDetail, useApiSpecs } from "../api/hooks";
import type { ScanParams } from "../api/types";
import { QueryState } from "./QueryState";

export interface ApiOptions {
  import_id: string;
  server_url: string;
  inventory_only: boolean;
  check_unauth_baseline: boolean;
  check_error_leakage: boolean;
  check_config: boolean;
}

export const DEFAULT_API_OPTIONS: ApiOptions = {
  import_id: "",
  server_url: "",
  inventory_only: true,
  check_unauth_baseline: false,
  check_error_leakage: true,
  check_config: true,
};

/** Only safe, non-gated options are exposed here; IDOR / mass-write / rate probes stay off
 *  (they need test identities, fixtures and acknowledgement configured elsewhere). */
export function apiParams(o: ApiOptions): ScanParams {
  const p: ScanParams = { import_id: o.import_id, inventory_only: o.inventory_only };
  if (o.server_url) p.server_url = o.server_url;
  if (!o.inventory_only) {
    p.check_unauth_baseline = o.check_unauth_baseline;
    p.check_error_leakage = o.check_error_leakage;
    p.check_config = o.check_config;
  }
  return p;
}

export function ApiScanOptions({ projectId, value, onChange }: { projectId: string; value: ApiOptions; onChange: (v: ApiOptions) => void }) {
  const specs = useApiSpecs(projectId);
  const detail = useApiSpecDetail(projectId, value.import_id || null);
  const set = <K extends keyof ApiOptions>(k: K, v: ApiOptions[K]) => onChange({ ...value, [k]: v });
  return (
    <Stack gap="xs" aria-label="API scan options" role="group">
      <QueryState query={specs} loadingLabel="Loading specs…">
        {(list) => list.length === 0 ? (
          <Alert color="yellow" variant="light" role="note">Import an API spec first (API specifications page), then start a scan.</Alert>
        ) : (
          <Select label="API specification" placeholder="Choose an imported spec" required
            value={value.import_id || null} onChange={(v) => set("import_id", v ?? "")}
            data={list.map((s) => ({ value: s.import_id, label: `${s.display_filename} (${s.operation_count} ops)` }))} />
        )}
      </QueryState>
      <Switch label="Inventory only (no network requests)" checked={value.inventory_only}
        onChange={(e) => set("inventory_only", e.currentTarget.checked)} />
      {!value.inventory_only && (
        <>
          {detail.data && (
            <Select label="Server (must be in scope)" placeholder="Pick an in-scope server"
              value={value.server_url || null} onChange={(v) => set("server_url", v ?? "")}
              data={detail.data.servers.map((s) => ({ value: s.expanded, label: `${s.expanded}${s.in_scope ? "" : " — out of scope"}`, disabled: !s.in_scope }))} />
          )}
          <Switch label="Error-leakage checks (stack traces, verbose errors)" checked={value.check_error_leakage}
            onChange={(e) => set("check_error_leakage", e.currentTarget.checked)} />
          <Switch label="Config checks (headers, CORS, transport, version)" checked={value.check_config}
            onChange={(e) => set("check_config", e.currentTarget.checked)} />
          <Switch label="Unauthenticated baseline on protected operations" checked={value.check_unauth_baseline}
            onChange={(e) => set("check_unauth_baseline", e.currentTarget.checked)} />
          <Text size="xs" c="dimmed">
            BOLA/IDOR, mass-assignment writes and rate-limit probes are disabled here: they require two test identities,
            an object-ownership map, test-safe operations with fixtures and cleanup, and an explicit risk acknowledgement.
          </Text>
        </>
      )}
      <Group />
    </Stack>
  );
}
