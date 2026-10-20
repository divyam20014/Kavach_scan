import { Alert, Badge, Group, List, NumberInput, SimpleGrid, Stack, Switch, Table, Text, TextInput, Title } from "@mantine/core";
import type { ScanParams, WebProfilePreview, WebScanProfile } from "../api/types";
import { humanize } from "../lib/format";

export interface WebOptions {
  respect_robots: boolean;
  tls_verify: boolean;
  check_cors: boolean;
  run_tls_tool: boolean;
  max_pages: number | "";
  max_depth: number | "";
  seed_paths: string;
}

export const DEFAULT_WEB_OPTIONS: WebOptions = {
  respect_robots: true,
  tls_verify: true,
  check_cors: true,
  run_tls_tool: true,
  max_pages: "",
  max_depth: "",
  seed_paths: "",
};

/** Start-request parameters: only values that differ from defaults are sent. */
export function webParams(o: WebOptions): ScanParams {
  const p: ScanParams = {};
  (["respect_robots", "tls_verify", "check_cors", "run_tls_tool"] as const).forEach((k) => {
    if (!o[k]) p[k] = false;
  });
  if (o.max_pages !== "") p.max_pages = o.max_pages;
  if (o.max_depth !== "") p.max_depth = o.max_depth;
  if (o.seed_paths.trim()) p.seed_paths = o.seed_paths.trim();
  return p;
}

export function WebScanOptions({ value, onChange, limits }: { value: WebOptions; onChange: (v: WebOptions) => void; limits: { pages: number; depth: number } }) {
  const set = <K extends keyof WebOptions>(k: K, v: WebOptions[K]) => onChange({ ...value, [k]: v });
  return (
    <Stack gap="xs" aria-label="Web scan options" role="group">
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">
        <Switch label="Respect robots.txt while crawling" checked={value.respect_robots} onChange={(e) => set("respect_robots", e.currentTarget.checked)} />
        <Switch label="Verify TLS certificates while crawling" checked={value.tls_verify} onChange={(e) => set("tls_verify", e.currentTarget.checked)} />
        <Switch label="CORS check (1 request per origin)" checked={value.check_cors} onChange={(e) => set("check_cors", e.currentTarget.checked)} />
        <Switch label="Run sslyze/testssl.sh if installed" checked={value.run_tls_tool} onChange={(e) => set("run_tls_tool", e.currentTarget.checked)} />
        <NumberInput label={`Max pages (project limit ${limits.pages})`} min={1} max={limits.pages} value={value.max_pages} allowDecimal={false}
          onChange={(v) => set("max_pages", typeof v === "number" ? v : "")} placeholder={String(limits.pages)} />
        <NumberInput label={`Max depth (project limit ${limits.depth})`} min={0} max={limits.depth} value={value.max_depth} allowDecimal={false}
          onChange={(v) => set("max_depth", typeof v === "number" ? v : "")} placeholder={String(limits.depth)} />
      </SimpleGrid>
      <TextInput label="Extra start paths (comma separated, e.g. /app/, /docs/)" value={value.seed_paths} onChange={(e) => set("seed_paths", e.currentTarget.value)} />
    </Stack>
  );
}

export function WebProfileSummary({ preview }: { preview: WebProfilePreview }) {
  const { profile, problems, tls_tools } = preview;
  return (
    <Stack gap="xs">
      {problems.length > 0 && (
        <Alert color="red" title="These options are not valid" role="alert">
          {problems.map((p) => <Text size="sm" key={p}>✕ {p}</Text>)}
        </Alert>
      )}
      <ProfileView profile={profile} tlsTools={tls_tools} />
    </Stack>
  );
}

export function ProfileView({ profile, tlsTools }: { profile: WebScanProfile; tlsTools?: string[] }) {
  const enabled = profile.checks.filter((c) => c.enabled);
  const disabled = profile.checks.filter((c) => !c.enabled);
  const b = profile.budgets;
  return (
    <Stack gap="xs" aria-label="Web scan profile details">
      <Group gap="xs">
        <Badge color={profile.safe_mode ? "green" : "red"} variant="light">{profile.safe_mode ? "Safe mode: on" : "Safe mode: off"}</Badge>
        <Badge variant="outline">Rule catalog {profile.catalog_version}</Badge>
        <Badge variant="outline">Authentication: {profile.auth_profile ?? "none (unauthenticated)"}</Badge>
        <Badge variant="outline">robots.txt {profile.respect_robots ? "respected" : "ignored"}</Badge>
        <Badge variant="outline">TLS verify {profile.tls_verify ? "on" : "off"}</Badge>
      </Group>
      <Text size="sm">
        Budgets: {b.max_pages} pages · depth {b.max_depth} · {b.requests_per_second} req/s · concurrency {b.max_concurrency} ·{" "}
        {b.max_requests_per_target} requests per target · {Math.round(b.max_duration_seconds / 60)} min · {Math.round(b.max_response_bytes / 1024)} KB per response ·{" "}
        {b.max_redirects} redirects
      </Text>
      {tlsTools && <Text size="sm">TLS tools detected: {tlsTools.length ? tlsTools.join(", ") : "none (protocol/cipher checks will be reported as skipped)"}</Text>}
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="sm">
        <div>
          <Title order={3} size="h6">Enabled checks ({enabled.length})</Title>
          <Table aria-label="Enabled checks">
            <Table.Tbody>
              {enabled.map((c) => (
                <Table.Tr key={c.group}>
                  <Table.Td>✓ {c.label}</Table.Td>
                  <Table.Td><Badge size="xs" variant="outline">{humanize(c.kind)}</Badge></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </div>
        <div>
          <Title order={3} size="h6">Disabled / not run ({disabled.length})</Title>
          <Table aria-label="Disabled checks">
            <Table.Tbody>
              {disabled.map((c) => (
                <Table.Tr key={c.group}>
                  <Table.Td>✕ {c.label}<Text size="xs" c="dimmed">{c.reason}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </div>
      </SimpleGrid>
      {profile.limitations.length > 0 && (
        <details>
          <summary><Text span size="sm">Limitations ({profile.limitations.length})</Text></summary>
          <List size="sm">{profile.limitations.map((l) => <List.Item key={l}>{l}</List.Item>)}</List>
        </details>
      )}
    </Stack>
  );
}
