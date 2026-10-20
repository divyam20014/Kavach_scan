import { Alert, Badge, Group, List, NumberInput, SimpleGrid, Stack, Switch, Table, Text, Textarea, TextInput, Title } from "@mantine/core";
import type { ScanParams, SurfaceProfilePreview } from "../api/types";

export interface SurfaceOptions {
  hosts: string;
  ports: string;
  port_method: "auto" | "connect" | "nmap";
  max_hosts: number | "";
  passive_crtsh: boolean;
  probe_web: boolean;
  read_banners: boolean;
  tls_verify: boolean;
}

export const DEFAULT_SURFACE_OPTIONS: SurfaceOptions = {
  hosts: "",
  ports: "",
  port_method: "auto",
  max_hosts: "",
  passive_crtsh: false,
  probe_web: true,
  read_banners: true,
  tls_verify: true,
};

export function surfaceParams(o: SurfaceOptions): ScanParams {
  const p: ScanParams = {};
  if (o.hosts.trim()) p.hosts = o.hosts.trim();
  if (o.ports.trim()) p.ports = o.ports.trim();
  if (o.port_method !== "auto") p.port_method = o.port_method;
  if (o.max_hosts !== "") p.max_hosts = o.max_hosts;
  if (o.passive_crtsh) p.passive_crtsh = true;
  if (!o.probe_web) p.probe_web = false;
  if (!o.read_banners) p.read_banners = false;
  if (!o.tls_verify) p.tls_verify = false;
  return p;
}

export function SurfaceScanOptions({ value, onChange }: { value: SurfaceOptions; onChange: (v: SurfaceOptions) => void }) {
  const set = <K extends keyof SurfaceOptions>(k: K, v: SurfaceOptions[K]) => onChange({ ...value, [k]: v });
  return (
    <Stack gap="xs" aria-label="Attack surface options" role="group">
      <Textarea label="Additional hosts (manual or imported; newline or comma separated)" value={value.hosts}
        onChange={(e) => set("hosts", e.currentTarget.value)} autosize minRows={2} placeholder="host.example.com" />
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">
        <TextInput label="Ports (comma separated; blank = conservative default list)" value={value.ports}
          onChange={(e) => set("ports", e.currentTarget.value)} placeholder="22,80,443,3306" />
        <NumberInput label="Max in-scope hosts to scan" min={1} max={1000} value={value.max_hosts} allowDecimal={false}
          onChange={(v) => set("max_hosts", typeof v === "number" ? v : "")} placeholder="50" />
        <Switch label="Probe discovered web origins" checked={value.probe_web} onChange={(e) => set("probe_web", e.currentTarget.checked)} />
        <Switch label="Read service banners (passive; nothing sent)" checked={value.read_banners} onChange={(e) => set("read_banners", e.currentTarget.checked)} />
        <Switch label="Verify TLS on web origins" checked={value.tls_verify} onChange={(e) => set("tls_verify", e.currentTarget.checked)} />
        <Switch label="Query crt.sh for subdomains (third party)" checked={value.passive_crtsh} onChange={(e) => set("passive_crtsh", e.currentTarget.checked)} />
      </SimpleGrid>
      {value.passive_crtsh && (
        <Alert color="yellow" variant="light" role="note">
          crt.sh is a third-party Certificate Transparency service. Each authorized root domain is sent to it; no request is sent to the target.
        </Alert>
      )}
    </Stack>
  );
}

export function SurfaceProfileSummary({ preview }: { preview: SurfaceProfilePreview }) {
  const { profile, problems, target_problems, nmap } = preview;
  const p = profile.ports;
  return (
    <Stack gap="xs" aria-label="Surface scan profile">
      {(problems.length > 0 || target_problems.length > 0) && (
        <Alert color="red" title="These options or targets are not valid" role="alert">
          {[...target_problems, ...problems].map((t) => <Text size="sm" key={t}>✕ {t}</Text>)}
        </Alert>
      )}
      <Group gap="xs">
        <Badge variant="light">Ports: {p.tested.length} tested</Badge>
        <Badge variant="outline">Method: {profile.port_method}{profile.port_method !== "connect" && (nmap ? " (Nmap found)" : " (Nmap absent → TCP connect)")}</Badge>
        <Badge variant="outline">Max hosts: {profile.max_hosts}</Badge>
        <Badge variant="outline">DNS: A/AAAA/CNAME</Badge>
        {profile.roots.length > 0 && <Badge variant="outline">{profile.roots.length} root/target(s)</Badge>}
      </Group>
      <Text size="sm">Ports to test: {p.tested.join(", ") || "none in scope"}</Text>
      {Object.keys(p.not_tested).length > 0 && (
        <Text size="sm" c="dimmed">Not tested: {Object.entries(p.not_tested).map(([port, why]) => `${port} (${why})`).join("; ")}</Text>
      )}
      <Table aria-label="Candidate sources">
        <Table.Tbody>
          {profile.sources.map((s) => (
            <Table.Tr key={s.name}>
              <Table.Td>{s.enabled ? "✓" : "✕"} {s.label}</Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{s.disclosure}</Text></Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      <details>
        <summary><Text span size="sm">Limitations ({profile.limitations.length})</Text></summary>
        <List size="sm">{profile.limitations.map((l) => <List.Item key={l}>{l}</List.Item>)}</List>
      </details>
      <Title order={4} size="h6" style={{ display: "none" }}>profile</Title>
    </Stack>
  );
}
