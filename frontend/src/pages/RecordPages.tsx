import { Anchor, Badge, Card, Group, Pagination, Stack, Table, Text } from "@mantine/core";
import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useRecords } from "../api/hooks";
import type { Asset, Finding, Page, ScanJob } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { ScanStateLabel, SeverityLabel } from "../components/StatusLabel";
import { formatDateTime, humanize } from "../lib/format";

const PAGE_SIZE = 25;
const FILTER_KEYS = ["project_id", "scan_id", "severity", "analyst_status", "confidence", "asset_type", "state"];

function useFilters() {
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get("page") ?? "1"));
  const query: Record<string, string | string[] | number | undefined> = { offset: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE };
  const active: [string, string][] = [];
  for (const key of FILTER_KEYS) {
    const values = params.getAll(key);
    if (values.length) {
      query[key] = values;
      values.forEach((v) => active.push([key, v]));
    }
  }
  const setPage = (p: number) => {
    const next = new URLSearchParams(params);
    next.set("page", String(p));
    setParams(next);
  };
  return { query, active, page, setPage };
}

function ActiveFilters({ active, base }: { active: [string, string][]; base: string }) {
  if (active.length === 0) return null;
  return (
    <Group gap="xs" mb="sm" aria-label="Active filters">
      <Text size="sm">Filtered by:</Text>
      {active.map(([k, v]) => (
        <Badge key={`${k}=${v}`} variant="outline">
          {humanize(k)}: {k === "project_id" || k === "scan_id" ? v.slice(0, 12) + "…" : humanize(v)}
        </Badge>
      ))}
      <Anchor component={Link} to={base} size="sm">
        Clear filters
      </Anchor>
    </Group>
  );
}

function RecordList<T>({
  title,
  base,
  kind,
  emptyText,
  columns,
  row,
}: {
  title: string;
  base: string;
  kind: "findings" | "assets" | "scans";
  emptyText: ReactNode;
  columns: string[];
  row: (item: T) => ReactNode;
}) {
  const { query, active, page, setPage } = useFilters();
  const result = useRecords<Finding | Asset | ScanJob>(kind, query);
  return (
    <>
      <PageHeader title={title} crumbs={[{ label: "Dashboard", to: "/" }, { label: title }]} />
      <ActiveFilters active={active} base={base} />
      <QueryState query={result}>
        {(data) => {
          const pageData = data as unknown as Page<T>;
          return pageData.total === 0 ? (
            <Card withBorder>
              <EmptyState title={active.length ? `No ${title.toLowerCase()} match these filters` : `No ${title.toLowerCase()} yet`}>
                {emptyText}
              </EmptyState>
            </Card>
          ) : (
            <Stack>
              <Card withBorder p={0}>
                <Table.ScrollContainer minWidth={700}>
                  <Table striped>
                    <Table.Caption>{pageData.total} record(s)</Table.Caption>
                    <Table.Thead>
                      <Table.Tr>
                        {columns.map((c) => (
                          <Table.Th scope="col" key={c}>
                            {c}
                          </Table.Th>
                        ))}
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>{pageData.items.map(row)}</Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              </Card>
              {pageData.total > PAGE_SIZE && (
                <Pagination total={Math.ceil(pageData.total / PAGE_SIZE)} value={page} onChange={setPage} aria-label={`${title} pages`} />
              )}
            </Stack>
          );
        }}
      </QueryState>
    </>
  );
}

const projectLink = (id: string) => (
  <Anchor component={Link} to={`/projects/${id}`} size="sm">
    {id.slice(0, 12)}…
  </Anchor>
);

export function FindingsPage() {
  return (
    <RecordList<Finding>
      title="Findings"
      base="/findings"
      kind="findings"
      emptyText="Findings are produced by scans (web scanner available; surface/API in Phases 06–07) and imports (Phase 08)."
      columns={["Title", "Severity", "Confidence", "Analyst status", "Project", "Updated"]}
      row={(f) => (
        <Table.Tr key={f.finding_id}>
          <Table.Td>
            {f.title}
            {f.url && <Text size="xs" c="dimmed" style={{ wordBreak: "break-all" }}>{f.url}{f.parameter ? ` · ${f.parameter}` : ""}</Text>}
          </Table.Td>
          <Table.Td><SeverityLabel severity={f.severity} /></Table.Td>
          <Table.Td>{humanize(f.confidence)}</Table.Td>
          <Table.Td>{humanize(f.analyst_status)}</Table.Td>
          <Table.Td>{projectLink(f.project_id)}</Table.Td>
          <Table.Td>{formatDateTime(f.updated_at)}</Table.Td>
        </Table.Tr>
      )}
    />
  );
}

export function AssetsPage() {
  return (
    <RecordList<Asset>
      title="Assets"
      base="/assets"
      kind="assets"
      emptyText="Assets are discovered by the attack surface mapper (Phase 06) or imported (Phase 08). None exist yet."
      columns={["Locator", "Type", "Scope status", "Confidence", "Project", "Last seen"]}
      row={(a) => (
        <Table.Tr key={a.asset_id}>
          <Table.Td style={{ wordBreak: "break-all" }}>{a.locator}</Table.Td>
          <Table.Td>{humanize(a.asset_type)}</Table.Td>
          <Table.Td>{humanize(a.scope_status)}</Table.Td>
          <Table.Td>{humanize(a.confidence)}</Table.Td>
          <Table.Td>{projectLink(a.project_id)}</Table.Td>
          <Table.Td>{formatDateTime(a.last_seen)}</Table.Td>
        </Table.Tr>
      )}
    />
  );
}

export function ScansPage() {
  return (
    <RecordList<ScanJob>
      title="Scans"
      base="/scans"
      kind="scans"
      emptyText="No jobs have been recorded. Start a job from a project page (web scanner available; surface/API scanners in Phases 06–07)."
      columns={["Scan", "Module", "State", "Project", "Updated"]}
      row={(s) => (
        <Table.Tr key={s.scan_id}>
          <Table.Td>
            <Anchor component={Link} to={`/projects/${s.project_id}/scans/${s.scan_id}`} size="sm">
              {s.scan_id.slice(0, 12)}…
            </Anchor>
          </Table.Td>
          <Table.Td>{humanize(s.module)}</Table.Td>
          <Table.Td><ScanStateLabel state={s.state} /></Table.Td>
          <Table.Td>{projectLink(s.project_id)}</Table.Td>
          <Table.Td>{formatDateTime(s.updated_at)}</Table.Td>
        </Table.Tr>
      )}
    />
  );
}
