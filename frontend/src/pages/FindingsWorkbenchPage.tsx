import { Anchor, Badge, Card, Group, MultiSelect, Pagination, Select, Stack, Table, Text, TextInput } from "@mantine/core";
import { Link, useSearchParams } from "react-router-dom";
import { useFindings } from "../api/hooks";
import type { AnalystStatus, Confidence, Severity } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { SeverityLabel } from "../components/StatusLabel";
import { formatDateTime, humanize } from "../lib/format";

const PAGE_SIZE = 25;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
const CONFIDENCES: Confidence[] = ["confirmed", "probable", "potential", "needs_review"];
const STATUSES: AnalystStatus[] = ["new", "confirmed", "false_positive", "accepted_risk", "fixed", "retest_needed", "needs_review"];
const MODULES = ["web_app", "attack_surface", "api_security", "import", "unknown"];

function useWorkbenchFilters() {
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get("page") ?? "1"));
  const get = (k: string) => params.get(k) ?? "";
  const getAll = (k: string) => params.getAll(k);
  const set = (k: string, v: string | string[] | null) => {
    const next = new URLSearchParams(params);
    next.delete(k);
    next.delete("page");
    if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
    else if (v) next.set(k, v);
    setParams(next);
  };
  const setPage = (p: number) => {
    const next = new URLSearchParams(params);
    next.set("page", String(p));
    setParams(next);
  };
  const query: Record<string, string | string[] | number | boolean | undefined> = {
    offset: (page - 1) * PAGE_SIZE,
    limit: PAGE_SIZE,
    sort: get("sort") || "updated_at",
    order: get("order") || "desc",
  };
  const project_id = get("project_id");
  const scan_id = get("scan_id");
  const q = get("q");
  const severity = getAll("severity");
  const confidence = getAll("confidence");
  const analyst_status = getAll("analyst_status");
  const module = getAll("module");
  const reviewed = get("reviewed");
  if (project_id) query.project_id = project_id;
  if (scan_id) query.scan_id = scan_id;
  if (q) query.q = q;
  if (severity.length) query.severity = severity;
  if (confidence.length) query.confidence = confidence;
  if (analyst_status.length) query.analyst_status = analyst_status;
  if (module.length) query.module = module;
  if (reviewed) query.reviewed = reviewed === "true";
  const hasFilters = Boolean(
    project_id || scan_id || q || severity.length || confidence.length || analyst_status.length ||
    module.length || reviewed,
  );
  return {
    query, page, setPage, get, set, project_id, scan_id, severity, confidence, analyst_status,
    module, q, reviewed, hasFilters,
  };
}

export function FindingsWorkbenchPage() {
  const f = useWorkbenchFilters();
  const result = useFindings(f.query);

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every canonical finding from live scans and imports — deduplicated, with an internal risk score (not CVSS) for triage."
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Findings" }]}
        actions={f.hasFilters && (
          <Anchor component={Link} to="/findings" size="sm">
            Clear filters
          </Anchor>
        )}
      />
      <Stack gap="md">
        {(f.project_id || f.scan_id) && (
          <Group gap="xs" aria-label="Active filters">
            {f.project_id && <Badge variant="outline">Project id: {f.project_id.slice(0, 12)}…</Badge>}
            {f.scan_id && <Badge variant="outline">Scan id: {f.scan_id.slice(0, 12)}…</Badge>}
          </Group>
        )}
        <Card withBorder>
          <Group gap="sm" wrap="wrap" align="flex-end">
            <TextInput
              label="Search" placeholder="Title, summary, URL…" value={f.q}
              onChange={(e) => f.set("q", e.currentTarget.value || null)}
              style={{ minWidth: 220 }}
            />
            <MultiSelect
              label="Severity" data={SEVERITIES.map((s) => ({ value: s, label: humanize(s) }))}
              value={f.severity} onChange={(v) => f.set("severity", v)} clearable style={{ minWidth: 180 }}
            />
            <MultiSelect
              label="Confidence" data={CONFIDENCES.map((c) => ({ value: c, label: humanize(c) }))}
              value={f.confidence} onChange={(v) => f.set("confidence", v)} clearable style={{ minWidth: 180 }}
            />
            <MultiSelect
              label="Analyst status" data={STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
              value={f.analyst_status} onChange={(v) => f.set("analyst_status", v)} clearable style={{ minWidth: 200 }}
            />
            <MultiSelect
              label="Module" data={MODULES.map((m) => ({ value: m, label: humanize(m) }))}
              value={f.module} onChange={(v) => f.set("module", v)} clearable style={{ minWidth: 180 }}
            />
            <Select
              label="Reviewed" data={[{ value: "true", label: "Reviewed" }, { value: "false", label: "Not reviewed" }]}
              value={f.reviewed || null} onChange={(v) => f.set("reviewed", v)} clearable style={{ minWidth: 150 }}
            />
            <Select
              label="Sort by"
              data={[
                { value: "updated_at", label: "Last seen" }, { value: "created_at", label: "First seen" },
                { value: "severity", label: "Severity" }, { value: "risk_score", label: "Risk score" },
                { value: "title", label: "Title" }, { value: "analyst_status", label: "Analyst status" },
              ]}
              value={f.get("sort") || "updated_at"} onChange={(v) => f.set("sort", v)} style={{ minWidth: 160 }}
            />
          </Group>
        </Card>
        <QueryState query={result} loadingLabel="Loading findings…">
          {(page) =>
            page.total === 0 ? (
              <Card withBorder>
                <EmptyState title="No findings match these filters">
                  Findings come from live scans (web/attack-surface/API) and imports.
                </EmptyState>
              </Card>
            ) : (
              <Stack>
                <Card withBorder p={0}>
                  <Table.ScrollContainer minWidth={900}>
                    <Table striped aria-label="Findings">
                      <Table.Caption>{page.total} finding(s)</Table.Caption>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th scope="col">Title</Table.Th>
                          <Table.Th scope="col">Severity</Table.Th>
                          <Table.Th scope="col">Confidence</Table.Th>
                          <Table.Th scope="col">Risk</Table.Th>
                          <Table.Th scope="col">Status</Table.Th>
                          <Table.Th scope="col">Module</Table.Th>
                          <Table.Th scope="col">Last seen</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {page.items.map((item) => (
                          <Table.Tr key={item.finding.finding_id}>
                            <Table.Td>
                              <Anchor component={Link} to={`/projects/${item.finding.project_id}/findings/${item.finding.finding_id}`} size="sm">
                                {item.finding.title}
                              </Anchor>
                              {item.finding.merged_into && (
                                <Text size="xs" c="dimmed">Merged into another finding</Text>
                              )}
                              {item.finding.url && (
                                <Text size="xs" c="dimmed" style={{ wordBreak: "break-all" }}>{item.finding.url}</Text>
                              )}
                            </Table.Td>
                            <Table.Td><SeverityLabel severity={item.finding.severity} /></Table.Td>
                            <Table.Td>{humanize(item.finding.confidence)}</Table.Td>
                            <Table.Td>
                              <Badge variant="outline" title={`Internal risk score: ${item.risk_score}/100 (not CVSS)`}>
                                {humanize(item.risk_tier)} ({item.risk_score})
                              </Badge>
                            </Table.Td>
                            <Table.Td>{humanize(item.finding.analyst_status)}</Table.Td>
                            <Table.Td>{humanize(item.module)}</Table.Td>
                            <Table.Td>{formatDateTime(item.finding.updated_at)}</Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                </Card>
                {page.total > PAGE_SIZE && (
                  <Pagination total={Math.ceil(page.total / PAGE_SIZE)} value={f.page} onChange={f.setPage} aria-label="Findings pages" />
                )}
              </Stack>
            )
          }
        </QueryState>
      </Stack>
    </>
  );
}
