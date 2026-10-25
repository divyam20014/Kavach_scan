import { Anchor, Card, Code, List, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { useFindings, useScanResult } from "../api/hooks";
import type { ApiSummary, CoverageRow, ScanJob } from "../api/types";
import { EmptyState, QueryState } from "../components/QueryState";
import { SeverityLabel } from "../components/StatusLabel";

const OUTCOME: Record<string, string> = { pass: "✓ pass", observation: "○ observation", finding: "▲ finding", skipped: "– skipped", error: "✕ error" };

function Stat({ label, value }: { label: string; value: number | string }) {
  return <Card withBorder padding="sm"><Text size="xs" c="dimmed">{label}</Text><Text fw={700} size="xl">{value}</Text></Card>;
}

function NotReady({ scan }: { scan: ScanJob }) {
  const running = ["queued", "validating", "running"].includes(scan.state);
  return <Text size="sm" c="dimmed">{running ? "Results are written when the job finishes." : "This job produced no API results."}</Text>;
}

export function ApiSummaryPanel({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const summary = useScanResult<ApiSummary>(scan.project_id, scan.scan_id, "summary", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={summary} loadingLabel="Loading API summary…">
      {(s) => (
        <Stack gap="md">
          {s.stopped_early && <Text size="sm" role="status">! Stopped early: {s.stopped_early}.</Text>}
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }}>
            <Stat label="Operations" value={s.operations_total} />
            <Stat label="Operations tested" value={s.operations_tested.length} />
            <Stat label="Requests sent" value={s.requests_sent} />
            <Stat label="New findings" value={s.findings_created} />
            <Stat label="Mode" value={s.inventory_only ? "inventory" : "checks"} />
            <Stat label="IDOR" value={s.idor_enabled ? "on" : "off"} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Card withBorder component="section" aria-labelledby="spec-h">
              <Title order={2} size="h4" id="spec-h" mb="sm">Spec & server</Title>
              <Text size="sm">Spec: {s.spec} ({s.spec_kind} {s.spec_version})</Text>
              <Text size="sm">Server: {s.server || <Text span c="dimmed">none contacted (offline/out-of-scope)</Text>}</Text>
              <Text size="sm">Auth aliases used: {s.auth_aliases_used.join(", ") || "none"}</Text>
              {s.remote_refs.length > 0 && <Text size="sm" c="dimmed">{s.remote_refs.length} remote $ref(s) were not fetched.</Text>}
            </Card>
            <Card withBorder component="section" aria-labelledby="out-h">
              <Title order={2} size="h4" id="out-h" mb="sm">Check outcomes</Title>
              <Table aria-label="Check outcome counts">
                <Table.Tbody>
                  {s.check_outcomes.map((c) => (
                    <Table.Tr key={c.outcome}><Table.Th scope="row">{OUTCOME[c.outcome] ?? c.outcome}</Table.Th><Table.Td ta="right">{c.count}</Table.Td></Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
              <Text size="xs" c="dimmed" mt="xs">A skipped precondition is never a pass.</Text>
            </Card>
          </SimpleGrid>
          <Card withBorder component="section" aria-labelledby="lim-h">
            <Title order={2} size="h4" id="lim-h" mb="sm">Coverage & limits</Title>
            <Text size="sm">Tested operations: {s.operations_tested.join(", ") || "none"}</Text>
            {Object.keys(s.operations_skipped).length > 0 && (
              <List size="sm" mt="xs">{Object.entries(s.operations_skipped).map(([op, why]) => <List.Item key={op}>{op}: {why}</List.Item>)}</List>
            )}
            <List size="sm" mt="xs">{s.limitations.map((l) => <List.Item key={l}>{l}</List.Item>)}</List>
          </Card>
        </Stack>
      )}
    </QueryState>
  );
}

export function ApiCoverageTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const coverage = useScanResult<{ catalog_version: string; results: CoverageRow[] }>(scan.project_id, scan.scan_id, "coverage", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={coverage}>
      {(data) => (
        <Card withBorder p={0}>
          <Table.ScrollContainer minWidth={760}>
            <Table striped aria-label="API coverage">
              <Table.Caption>{data.results.length} result(s) · catalog {data.catalog_version}</Table.Caption>
              <Table.Thead><Table.Tr>
                <Table.Th scope="col">Rule</Table.Th><Table.Th scope="col">Outcome</Table.Th>
                <Table.Th scope="col">Subject</Table.Th><Table.Th scope="col">Rationale</Table.Th>
              </Table.Tr></Table.Thead>
              <Table.Tbody>
                {data.results.slice(0, 1000).map((r, i) => (
                  <Table.Tr key={`${r.rule_id}-${i}`}>
                    <Table.Td><Code>{r.rule_id}</Code><Text size="xs">{r.title}</Text></Table.Td>
                    <Table.Td>{OUTCOME[r.outcome] ?? r.outcome}{r.severity && <><br /><SeverityLabel severity={r.severity} /></>}</Table.Td>
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

export function ApiFindingsTab({ scan }: { scan: ScanJob }) {
  const findings = useFindings({ project_id: scan.project_id, scan_id: scan.scan_id, limit: 100, sort: "severity" });
  return (
    <Stack gap="sm">
      <Anchor component={Link} to={`/findings?project_id=${scan.project_id}&scan_id=${scan.scan_id}`} size="sm">Open these findings in the global findings view</Anchor>
      <QueryState query={findings}>
        {(page) => page.total === 0 ? (
          <Card withBorder><EmptyState title="No findings linked to this job">Checks that passed or were skipped are on the Coverage tab.</EmptyState></Card>
        ) : (
          <Card withBorder p={0}>
            <Table.ScrollContainer minWidth={640}>
              <Table striped aria-label="Findings from this job">
                <Table.Caption>{page.total} finding(s)</Table.Caption>
                <Table.Thead><Table.Tr><Table.Th scope="col">Title</Table.Th><Table.Th scope="col">Severity</Table.Th><Table.Th scope="col">Rule</Table.Th></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {page.items.map(({ finding: f }) => (
                    <Table.Tr key={f.finding_id}><Table.Td><Anchor component={Link} to={`/projects/${f.project_id}/findings/${f.finding_id}`} size="sm">{f.title}</Anchor>{f.component && <Text size="xs" c="dimmed">{f.component}</Text>}</Table.Td><Table.Td><SeverityLabel severity={f.severity} /></Table.Td><Table.Td><Code>{f.rule_id}</Code></Table.Td></Table.Tr>
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
