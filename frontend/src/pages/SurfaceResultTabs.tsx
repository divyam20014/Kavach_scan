import { Anchor, Card, Code, List, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { useRecords, useScanResult } from "../api/hooks";
import type { CoverageRow, Finding, ScanJob, SurfaceChanges, SurfaceSummary } from "../api/types";
import { EmptyState, QueryState } from "../components/QueryState";
import { SeverityLabel } from "../components/StatusLabel";
import { humanize } from "../lib/format";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <Card withBorder padding="sm">
      <Text size="xs" c="dimmed">{label}</Text>
      <Text fw={700} size="xl">{value}</Text>
    </Card>
  );
}

function NotReady({ scan }: { scan: ScanJob }) {
  const running = ["queued", "validating", "running"].includes(scan.state);
  return <Text size="sm" c="dimmed">{running ? "Results are written when the job finishes (partial results are kept if it is cancelled or stopped by a limit)." : "This job produced no surface-mapping results."}</Text>;
}

export function SurfaceSummaryPanel({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const summary = useScanResult<SurfaceSummary>(scan.project_id, scan.scan_id, "summary", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={summary} loadingLabel="Loading surface summary…">
      {(s) => (
        <Stack gap="md">
          {s.stopped_early && <Text size="sm" role="status">! Stopped early: {s.stopped_early}. Results are partial.</Text>}
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }}>
            <Stat label="Candidates" value={s.candidates} />
            <Stat label="Hosts checked" value={Object.keys(s.hosts_checked).length} />
            <Stat label="Open services" value={s.open_services.length} />
            <Stat label="Web origins" value={s.web_origins.length} />
            <Stat label="New findings" value={s.findings_created} />
            <Stat label="Blocked addresses" value={s.dns.blocked_addresses} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Card withBorder component="section" aria-labelledby="cand-h">
              <Title order={2} size="h4" id="cand-h" mb="sm">Candidates by status</Title>
              <Table aria-label="Candidate status counts">
                <Table.Tbody>
                  {Object.entries(s.candidates_by_status).map(([k, v]) => (
                    <Table.Tr key={k}><Table.Th scope="row">{humanize(k)}</Table.Th><Table.Td ta="right">{v}</Table.Td></Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
              <Text size="xs" c="dimmed" mt="xs">Discovery alone does not grant scan permission: only in-scope hosts are port-checked and probed.</Text>
            </Card>
            <Card withBorder component="section" aria-labelledby="src-h">
              <Title order={2} size="h4" id="src-h" mb="sm">Sources & DNS</Title>
              <List size="sm">
                {s.sources.map((src) => <List.Item key={src.name}>{src.label}: {src.candidates} candidate(s){src.error ? ` — ${src.error}` : ""}<Text size="xs" c="dimmed">{src.disclosure}</Text></List.Item>)}
              </List>
              <Text size="sm" mt="xs">DNS: {s.dns.resolved} resolved, {s.dns.unresolved} unresolved, {s.dns.not_attempted} not attempted, {s.dns.blocked_addresses} blocked.</Text>
              <Text size="xs" c="dimmed">{s.dns.method}</Text>
            </Card>
          </SimpleGrid>
          <Card withBorder component="section" aria-labelledby="ports-h">
            <Title order={2} size="h4" id="ports-h" mb="sm">Port coverage</Title>
            <Text size="sm">Method: <strong>{s.port_method}</strong>{s.tool_versions.nmap ? ` (${s.tool_versions.nmap})` : " (TCP connect)"}</Text>
            <Text size="sm">Tested: {s.ports_tested.join(", ") || "none"}</Text>
            {Object.keys(s.ports_not_tested).length > 0 && (
              <Text size="sm" c="dimmed">Not tested: {Object.entries(s.ports_not_tested).map(([p, w]) => `${p} (${w})`).join("; ")}</Text>
            )}
          </Card>
          {s.limitations.length > 0 && (
            <Card withBorder component="section" aria-labelledby="lim-h">
              <Title order={2} size="h4" id="lim-h" mb="sm">Scan coverage & limits</Title>
              <List size="sm">{s.limitations.map((l) => <List.Item key={l}>{l}</List.Item>)}</List>
            </Card>
          )}
        </Stack>
      )}
    </QueryState>
  );
}

export function SurfaceHostsTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const summary = useScanResult<SurfaceSummary>(scan.project_id, scan.scan_id, "summary", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={summary}>
      {(s) => (
        <Stack gap="md">
          <Card withBorder p={0}>
            <Table.ScrollContainer minWidth={720}>
              <Table striped aria-label="Open services">
                <Table.Caption>{s.open_services.length} open service(s)</Table.Caption>
                <Table.Thead><Table.Tr>
                  <Table.Th scope="col">Host</Table.Th><Table.Th scope="col">IP</Table.Th><Table.Th scope="col">Port</Table.Th>
                  <Table.Th scope="col">Service</Table.Th><Table.Th scope="col">Banner (sanitized)</Table.Th>
                </Table.Tr></Table.Thead>
                <Table.Tbody>
                  {s.open_services.map((o) => (
                    <Table.Tr key={`${o.ip}:${o.port}`}>
                      <Table.Td>{o.host}</Table.Td><Table.Td>{o.ip}</Table.Td><Table.Td>{o.port}</Table.Td>
                      <Table.Td>{[o.service, o.product, o.version].filter(Boolean).join(" ")}</Table.Td>
                      <Table.Td style={{ wordBreak: "break-all" }}>{o.banner || "—"}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Card>
          <Card withBorder component="section" aria-labelledby="nc-h">
            <Title order={2} size="h4" id="nc-h" mb="sm">Hosts not scanned ({Object.keys(s.hosts_not_checked).length})</Title>
            {Object.keys(s.hosts_not_checked).length === 0 ? <Text size="sm" c="dimmed">All in-scope hosts were checked.</Text> : (
              <List size="sm">{Object.entries(s.hosts_not_checked).map(([h, why]) => <List.Item key={h}>{h}: {why}</List.Item>)}</List>
            )}
          </Card>
        </Stack>
      )}
    </QueryState>
  );
}

export function SurfaceOriginsTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const summary = useScanResult<SurfaceSummary>(scan.project_id, scan.scan_id, "summary", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={summary}>
      {(s) => s.web_origins.length === 0 ? (
        <Card withBorder><EmptyState title="No web origins discovered">No open HTTP(S) origins were found on the scanned ports.</EmptyState></Card>
      ) : (
        <Card withBorder p={0}>
          <Table.ScrollContainer minWidth={720}>
            <Table striped aria-label="Web origins">
              <Table.Thead><Table.Tr>
                <Table.Th scope="col">Origin</Table.Th><Table.Th scope="col">Status</Table.Th>
                <Table.Th scope="col">Title</Table.Th><Table.Th scope="col">Server</Table.Th><Table.Th scope="col">TLS</Table.Th>
              </Table.Tr></Table.Thead>
              <Table.Tbody>
                {s.web_origins.map((o) => (
                  <Table.Tr key={o.origin}>
                    <Table.Td style={{ wordBreak: "break-all" }}>{o.origin}</Table.Td>
                    <Table.Td>{o.status ?? <Text span size="sm" c="red">{o.error}</Text>}</Table.Td>
                    <Table.Td>{o.title || "—"}</Table.Td>
                    <Table.Td>{o.server || "—"}</Table.Td>
                    <Table.Td>{o.tls && "verified" in o.tls ? (o.tls.verified ? "verified" : "invalid") : "—"}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      )}
    </QueryState>
  );
}

export function SurfaceChangesTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const changes = useScanResult<SurfaceChanges>(scan.project_id, scan.scan_id, "changes", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={changes}>
      {(c) => c.baseline ? (
        <Card withBorder><EmptyState title="Baseline inventory">This is the first completed surface scan for the project; later scans compare against it.</EmptyState></Card>
      ) : (
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <Card withBorder component="section" aria-labelledby="ch-hosts">
            <Title order={2} size="h4" id="ch-hosts" mb="sm">Host changes</Title>
            <List size="sm">
              {c.new_hosts.map((h) => <List.Item key={`n${h}`}>＋ new host {h}</List.Item>)}
              {c.not_observed_hosts.map((h) => <List.Item key={`g${h}`}>· not observed this scan: {h}</List.Item>)}
              {c.status_changes.map((s) => <List.Item key={`s${s.host}`}>{s.host}: {s.from} → {s.to}</List.Item>)}
              {c.ip_changes.map((i) => <List.Item key={`i${i.host}`}>{i.host} IPs: {i.from.join(",") || "none"} → {i.to.join(",") || "none"}</List.Item>)}
            </List>
          </Card>
          <Card withBorder component="section" aria-labelledby="ch-ports">
            <Title order={2} size="h4" id="ch-ports" mb="sm">Port & origin changes</Title>
            <List size="sm">
              {c.opened_ports.map((p) => <List.Item key={`o${p.host}${p.port}`}>＋ {p.host} port {p.port} now open</List.Item>)}
              {c.closed_ports.map((p) => <List.Item key={`c${p.host}${p.port}`}>－ {p.host} port {p.port} now closed</List.Item>)}
              {c.new_origins.map((o) => <List.Item key={`no${o}`}>＋ new origin {o}</List.Item>)}
            </List>
            {c.opened_ports.length + c.closed_ports.length + c.new_origins.length === 0 && <Text size="sm" c="dimmed">No port or origin changes.</Text>}
          </Card>
        </SimpleGrid>
      )}
    </QueryState>
  );
}

const OUTCOME_LABEL: Record<string, string> = { pass: "✓ pass", observation: "○ observation", finding: "▲ finding", skipped: "– skipped", error: "✕ error" };

export function SurfaceCoverageTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const coverage = useScanResult<{ catalog_version: string; results: CoverageRow[] }>(scan.project_id, scan.scan_id, "coverage", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={coverage}>
      {(data) => (
        <Card withBorder p={0}>
          <Table.ScrollContainer minWidth={760}>
            <Table striped aria-label="Surface coverage">
              <Table.Caption>{data.results.length} result(s) · catalog {data.catalog_version}</Table.Caption>
              <Table.Thead><Table.Tr>
                <Table.Th scope="col">Rule</Table.Th><Table.Th scope="col">Outcome</Table.Th>
                <Table.Th scope="col">Subject</Table.Th><Table.Th scope="col">Rationale</Table.Th>
              </Table.Tr></Table.Thead>
              <Table.Tbody>
                {data.results.slice(0, 1000).map((r, i) => (
                  <Table.Tr key={`${r.rule_id}-${i}`}>
                    <Table.Td><Code>{r.rule_id}</Code><Text size="xs">{r.title}</Text></Table.Td>
                    <Table.Td>{OUTCOME_LABEL[r.outcome] ?? r.outcome}{r.severity && <><br /><SeverityLabel severity={r.severity} /></>}</Table.Td>
                    <Table.Td style={{ wordBreak: "break-all" }}>{r.subject}</Table.Td>
                    <Table.Td style={{ wordBreak: "break-word" }}>{r.rationale}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      )}
    </QueryState>
  );
}

export function SurfaceFindingsTab({ scan }: { scan: ScanJob }) {
  const findings = useRecords<Finding>("findings", { project_id: scan.project_id, scan_id: scan.scan_id, limit: 100, sort: "severity" });
  return (
    <Stack gap="sm">
      <Anchor component={Link} to={`/findings?project_id=${scan.project_id}&scan_id=${scan.scan_id}`} size="sm">Open these findings in the global findings view</Anchor>
      <QueryState query={findings}>
        {(page) => page.total === 0 ? (
          <Card withBorder><EmptyState title="No findings linked to this job">Discovery is not a vulnerability. Checks that passed or were skipped are on the Coverage tab.</EmptyState></Card>
        ) : (
          <Card withBorder p={0}>
            <Table.ScrollContainer minWidth={640}>
              <Table striped aria-label="Findings from this job">
                <Table.Caption>{page.total} finding(s)</Table.Caption>
                <Table.Thead><Table.Tr><Table.Th scope="col">Title</Table.Th><Table.Th scope="col">Severity</Table.Th><Table.Th scope="col">Rule</Table.Th></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {page.items.map((f) => (
                    <Table.Tr key={f.finding_id}><Table.Td>{f.title}{f.component && <Text size="xs" c="dimmed">{f.component}</Text>}</Table.Td><Table.Td><SeverityLabel severity={f.severity} /></Table.Td><Table.Td><Code>{f.rule_id}</Code></Table.Td></Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Card>
        )}
      </QueryState>
    </Stack>
  );
}
