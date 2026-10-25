import { Anchor, Badge, Card, Code, Group, List, SegmentedControl, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useFindings, useScanResult } from "../api/hooks";
import type { CheckOutcome, CoverageRow, PagesInventory, ScanJob, WebScanSummary } from "../api/types";
import { EmptyState, QueryState } from "../components/QueryState";
import { SeverityLabel } from "../components/StatusLabel";
import { humanize } from "../lib/format";

const OUTCOME_LABEL: Record<CheckOutcome, string> = {
  pass: "✓ pass",
  observation: "○ observation",
  finding: "▲ finding",
  skipped: "– skipped",
  error: "✕ error",
};

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <Card withBorder padding="sm">
      <Text size="xs" c="dimmed">{label}</Text>
      <Text fw={700} size="xl">{value}</Text>
    </Card>
  );
}

function NotReady({ scan }: { scan: ScanJob }) {
  return (
    <Text size="sm" c="dimmed">
      {scan.state === "queued" || scan.state === "validating" || scan.state === "running"
        ? "Results are written when the job finishes (partial results are kept if it is cancelled or stopped by a limit)."
        : "This job produced no web scanner results."}
    </Text>
  );
}

export function WebSummaryPanel({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const summary = useScanResult<WebScanSummary>(scan.project_id, scan.scan_id, "summary", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={summary} loadingLabel="Loading scan summary…">
      {(s) => (
        <Stack gap="md">
          {s.stopped_early && <Text size="sm" role="status">! Stopped early: {s.stopped_early}. The results below are partial.</Text>}
          <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }}>
            <Stat label="Pages fetched" value={s.pages_fetched} />
            <Stat label="Endpoints" value={s.endpoints_discovered} />
            <Stat label="Requests sent" value={s.requests_sent} />
            <Stat label="New findings" value={s.findings_created} />
            <Stat label="Re-observed" value={s.findings_reobserved} />
            <Stat label="Out-of-scope blocks" value={s.scope_blocked + s.redirects_blocked} />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Card withBorder component="section" aria-labelledby="checks-h">
              <Title order={2} size="h4" id="checks-h" mb="sm">Check outcomes</Title>
              <Table aria-label="Check outcome counts">
                <Table.Tbody>
                  {(Object.keys(OUTCOME_LABEL) as CheckOutcome[]).map((o) => (
                    <Table.Tr key={o}>
                      <Table.Th scope="row">{OUTCOME_LABEL[o]}</Table.Th>
                      <Table.Td ta="right">{s.check_outcomes.find((c) => c.outcome === o)?.count ?? 0}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
              <Text size="xs" c="dimmed" mt="xs">A skipped or errored check is never counted as a pass. Rule catalog {s.catalog_version}.</Text>
            </Card>
            <Card withBorder component="section" aria-labelledby="activity-h">
              <Title order={2} size="h4" id="activity-h" mb="sm">Request activity</Title>
              <Table aria-label="Request activity">
                <Table.Tbody>
                  {([
                    ["Request errors", s.request_errors],
                    ["Retries", s.request_retries],
                    ["Rate-limited responses (429/503)", s.rate_limited_responses],
                    ["Scope blocks", s.scope_blocked],
                    ["Redirects not followed (out of scope)", s.redirects_blocked],
                    ["Out-of-scope links not requested", s.out_of_scope_links],
                    ["Forms discovered", s.forms_discovered],
                    ["Parameters discovered", s.parameters_discovered],
                  ] as const).map(([k, v]) => (
                    <Table.Tr key={k}>
                      <Table.Th scope="row">{k}</Table.Th>
                      <Table.Td ta="right">{v}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Card>
          </SimpleGrid>
          <Card withBorder component="section" aria-labelledby="components-h">
            <Title order={2} size="h4" id="components-h" mb="sm">Detected components</Title>
            {s.components.length === 0 ? (
              <Text size="sm" c="dimmed">No components identified.</Text>
            ) : (
              <Table.ScrollContainer minWidth={560}>
                <Table aria-label="Detected components">
                  <Table.Thead>
                    <Table.Tr><Table.Th scope="col">Component</Table.Th><Table.Th scope="col">Version</Table.Th><Table.Th scope="col">Confidence</Table.Th><Table.Th scope="col">Source</Table.Th></Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {s.components.map((c) => (
                      <Table.Tr key={`${c.name}-${c.version}`}>
                        <Table.Td>{c.name}</Table.Td>
                        <Table.Td>{c.version || "unknown"}</Table.Td>
                        <Table.Td>{humanize(c.confidence)}</Table.Td>
                        <Table.Td>{c.sources.join(", ")}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
            <Text size="xs" c="dimmed" mt="xs">Observations only: a detected version is not proof of a vulnerability. CVE matching runs only with a locally imported catalog.</Text>
            <Text size="sm" mt="xs">Tool versions: {Object.keys(s.tool_versions).length ? Object.entries(s.tool_versions).map(([k, v]) => <Code key={k} mr={4}>{k}: {v}</Code>) : "no external tool ran"}</Text>
          </Card>
        </Stack>
      )}
    </QueryState>
  );
}

export function WebWarningsPanel({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const summary = useScanResult<WebScanSummary>(scan.project_id, scan.scan_id, "summary", ready);
  if (!ready) return null;
  return (
    <QueryState query={summary}>
      {(s) => (
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <Card withBorder component="section" aria-labelledby="crawl-h">
            <Title order={2} size="h4" id="crawl-h" mb="sm">Crawl: skipped and limited</Title>
            {s.crawl_limit && <Text size="sm">! {s.crawl_limit}</Text>}
            <List size="sm">
              {Object.entries(s.crawl_skipped).map(([k, v]) => <List.Item key={k}>{humanize(k)}: {v}</List.Item>)}
              {Object.entries(s.robots).map(([o, v]) => <List.Item key={o}>robots.txt {o}: {v}</List.Item>)}
              {Object.entries(s.out_of_scope_hosts).map(([h, v]) => <List.Item key={h}>Out-of-scope host {h}: {v} link(s), not requested</List.Item>)}
            </List>
          </Card>
          <Card withBorder component="section" aria-labelledby="limits-h">
            <Title order={2} size="h4" id="limits-h" mb="sm">Limitations of this scan</Title>
            <List size="sm">{s.limitations.map((l) => <List.Item key={l}>{l}</List.Item>)}</List>
          </Card>
        </SimpleGrid>
      )}
    </QueryState>
  );
}

export function WebPagesTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const pages = useScanResult<PagesInventory>(scan.project_id, scan.scan_id, "pages", ready);
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={pages} loadingLabel="Loading inventory…">
      {(inv) => (
        <Stack gap="md">
          <Card withBorder p={0}>
            <Table.ScrollContainer minWidth={820}>
              <Table striped aria-label="Pages and endpoints">
                <Table.Caption>{inv.pages.length} page(s) fetched</Table.Caption>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th scope="col">URL</Table.Th>
                    <Table.Th scope="col">Status</Table.Th>
                    <Table.Th scope="col">Type</Table.Th>
                    <Table.Th scope="col">Title</Table.Th>
                    <Table.Th scope="col">Depth</Table.Th>
                    <Table.Th scope="col">Redirects</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {inv.pages.map((p) => (
                    <Table.Tr key={p.url}>
                      <Table.Td style={{ wordBreak: "break-all" }}>
                        {p.url}
                        {p.parameters.length > 0 && <Text size="xs" c="dimmed">params: {p.parameters.join(", ")}</Text>}
                      </Table.Td>
                      <Table.Td>{p.status ?? <Text span size="sm" c="red">{p.error || "no response"}</Text>}</Table.Td>
                      <Table.Td>{p.content_type || "—"}{p.truncated && <Badge size="xs" ml={4} variant="outline">truncated</Badge>}</Table.Td>
                      <Table.Td>{p.title || "—"}</Table.Td>
                      <Table.Td>{p.depth}</Table.Td>
                      <Table.Td style={{ wordBreak: "break-all" }}>
                        {p.redirect_chain.length > 0 ? `${p.redirect_chain.length} → ${p.final_url}` : "—"}
                        {p.redirect_blocked_to && <Text size="xs" c="orange">blocked (out of scope): {p.redirect_blocked_to}</Text>}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Card>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Card withBorder component="section" aria-labelledby="forms-h">
              <Title order={2} size="h4" id="forms-h" mb="sm">Forms ({inv.forms.length})</Title>
              {inv.forms.length === 0 ? <Text size="sm" c="dimmed">No forms found.</Text> : (
                <List size="sm">
                  {inv.forms.slice(0, 200).map((f, i) => (
                    <List.Item key={`${f.page}-${i}`} style={{ wordBreak: "break-all" }}>
                      {f.method} {f.action} — fields: {f.fields.join(", ") || "none"}{f.login_form ? " (login form)" : ""}
                    </List.Item>
                  ))}
                </List>
              )}
              <Text size="xs" c="dimmed" mt="xs">Forms and parameters are inventory only; nothing was submitted.</Text>
            </Card>
            <Card withBorder component="section" aria-labelledby="params-h">
              <Title order={2} size="h4" id="params-h" mb="sm">Parameters ({inv.parameters.length})</Title>
              {inv.parameters.length === 0 ? <Text size="sm" c="dimmed">No query parameters seen.</Text> : (
                <Group gap={4}>{inv.parameters.slice(0, 300).map((p) => <Code key={p}>{p}</Code>)}</Group>
              )}
            </Card>
          </SimpleGrid>
        </Stack>
      )}
    </QueryState>
  );
}

export function WebFindingsTab({ scan }: { scan: ScanJob }) {
  const findings = useFindings({ project_id: scan.project_id, scan_id: scan.scan_id, limit: 100, sort: "severity" });
  return (
    <Stack gap="sm">
      <Anchor component={Link} to={`/findings?project_id=${scan.project_id}&scan_id=${scan.scan_id}`} size="sm">
        Open these findings in the global findings view
      </Anchor>
      <QueryState query={findings}>
        {(page) =>
          page.total === 0 ? (
            <Card withBorder><EmptyState title="No findings linked to this job">Checks that passed, were skipped or errored are listed on the Coverage tab.</EmptyState></Card>
          ) : (
            <Card withBorder p={0}>
              <Table.ScrollContainer minWidth={700}>
                <Table striped aria-label="Findings from this job">
                  <Table.Caption>{page.total} finding(s) last observed by this job</Table.Caption>
                  <Table.Thead>
                    <Table.Tr><Table.Th scope="col">Title</Table.Th><Table.Th scope="col">Severity</Table.Th><Table.Th scope="col">Confidence</Table.Th><Table.Th scope="col">Rule</Table.Th></Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {page.items.map(({ finding: f }) => (
                      <Table.Tr key={f.finding_id}>
                        <Table.Td>
                          <Anchor component={Link} to={`/projects/${f.project_id}/findings/${f.finding_id}`} size="sm">
                            {f.title}
                          </Anchor>
                          {f.url && <Text size="xs" c="dimmed" style={{ wordBreak: "break-all" }}>{f.url}{f.parameter ? ` · ${f.parameter}` : ""}</Text>}
                        </Table.Td>
                        <Table.Td><SeverityLabel severity={f.severity} /></Table.Td>
                        <Table.Td>{humanize(f.confidence)}</Table.Td>
                        <Table.Td><Code>{f.rule_id}</Code></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Card>
          )
        }
      </QueryState>
    </Stack>
  );
}

export function WebCoverageTab({ scan, ready }: { scan: ScanJob; ready: boolean }) {
  const coverage = useScanResult<{ catalog_version: string; results: CoverageRow[] }>(scan.project_id, scan.scan_id, "coverage", ready);
  const [filter, setFilter] = useState<"all" | CheckOutcome>("all");
  if (!ready) return <NotReady scan={scan} />;
  return (
    <QueryState query={coverage} loadingLabel="Loading coverage…">
      {(data) => {
        const rows = filter === "all" ? data.results : data.results.filter((r) => r.outcome === filter);
        return (
          <Stack gap="sm">
            <SegmentedControl
              aria-label="Filter coverage by outcome"
              value={filter}
              onChange={(v) => setFilter(v as typeof filter)}
              data={[{ label: "All", value: "all" }, ...(Object.keys(OUTCOME_LABEL) as CheckOutcome[]).map((o) => ({ label: humanize(o), value: o }))]}
            />
            <Card withBorder p={0}>
              <Table.ScrollContainer minWidth={820}>
                <Table striped aria-label="Check coverage">
                  <Table.Caption>{rows.length} result(s) · rule catalog {data.catalog_version}</Table.Caption>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th scope="col">Rule</Table.Th>
                      <Table.Th scope="col">Outcome</Table.Th>
                      <Table.Th scope="col">Subject</Table.Th>
                      <Table.Th scope="col">Rationale</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {rows.slice(0, 1000).map((r, i) => (
                      <Table.Tr key={`${r.rule_id}-${i}`}>
                        <Table.Td><Code>{r.rule_id}</Code><Text size="xs">{r.title}</Text></Table.Td>
                        <Table.Td>{OUTCOME_LABEL[r.outcome]}{r.severity && <><br /><SeverityLabel severity={r.severity} /></>}</Table.Td>
                        <Table.Td style={{ wordBreak: "break-all" }}>{r.subject}{r.parameter && <Text size="xs" c="dimmed">{r.parameter}</Text>}</Table.Td>
                        <Table.Td style={{ wordBreak: "break-word" }}>{r.rationale}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Card>
          </Stack>
        );
      }}
    </QueryState>
  );
}
