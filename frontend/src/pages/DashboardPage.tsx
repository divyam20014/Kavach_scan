import { Alert, Anchor, Button, Card, Group, Progress, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { useDashboard, useRecords } from "../api/hooks";
import { CONFIDENCES, SEVERITIES, type DashboardSummary, type ScanJob } from "../api/types";
import { KpiCard } from "../components/KpiCard";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { ScanStateLabel, SEVERITY, SeverityLabel } from "../components/StatusLabel";
import { formatDateTime, humanize } from "../lib/format";
import { projectLink } from "./RecordPages";

export function DashboardPage() {
  const query = useDashboard();
  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Every number is counted from stored records when this page loads. Nothing is estimated or sample data."
        actions={
          <Button component={Link} to="/projects/new">
            New project
          </Button>
        }
      />
      <QueryState query={query} loadingLabel="Loading dashboard…">
        {(data) => <DashboardBody data={data} />}
      </QueryState>
    </>
  );
}

function DashboardBody({ data }: { data: DashboardSummary }) {
  const { projects, scans, findings, assets } = data;
  return (
    <Stack gap="lg">
      {data.unreadable_records > 0 && (
        <Alert color="yellow" title="Some records could not be read" role="status">
          {data.unreadable_records} record(s) are corrupt or invalid and are excluded from these counts. See{" "}
          <Anchor component={Link} to="/settings">
            Settings &amp; storage
          </Anchor>{" "}
          to run an integrity check.
        </Alert>
      )}

      <section aria-labelledby="kpi-heading">
        <Title order={2} size="h4" id="kpi-heading" mb="sm">
          Overview
        </Title>
        <SimpleGrid cols={{ base: 1, xs: 2, md: 4 }} spacing="md">
          <KpiCard testId="kpi-projects" label="Projects" value={projects.total} to="/projects"
            hint={`${projects.active} active · ${projects.archived} archived`} />
          <KpiCard testId="kpi-scans" label="Scans" value={scans.total} to="/scans"
            hint={scans.last_scan_at ? `Last: ${humanize(scans.last_scan_state ?? "")} ${formatDateTime(scans.last_scan_at)}` : "No scans recorded"} />
          <KpiCard testId="kpi-active-scans" label="Active scans" value={scans.active}
            to="/scans?state=queued&state=validating&state=running" />
          <KpiCard testId="kpi-failed-scans" label="Failed scans" value={scans.failed} to="/scans?state=failed" />
          <KpiCard testId="kpi-critical-high" label="Critical & High findings" value={findings.by_severity.critical + findings.by_severity.high}
            to="/findings?severity=critical&severity=high" hint="Needs attention first" />
          <KpiCard testId="kpi-findings" label="Findings (unique records)" value={findings.total} to="/findings"
            hint={`${findings.open} open`} />
          <KpiCard testId="kpi-confirmed" label="Confirmed findings" value={findings.by_confidence.confirmed}
            to="/findings?confidence=confirmed" hint="Scanner confidence: confirmed" />
          <KpiCard testId="kpi-retest" label="Retest needed" value={findings.by_status.retest_needed}
            to="/findings?analyst_status=retest_needed" />
          <KpiCard testId="kpi-assets" label="Assets discovered" value={assets.total} to="/assets" />
        </SimpleGrid>
      </section>

      {projects.total === 0 ? (
        <Card withBorder>
          <EmptyState
            title="No projects yet"
            action={
              <Button component={Link} to="/projects/new">
                Create a project
              </Button>
            }
          >
            Start by creating a project with its authorization record and target scope, then run a web application,
            attack-surface or API security scan — or import results from an existing tool.
          </EmptyState>
        </Card>
      ) : (
        <AuthorizationAlerts data={data} />
      )}

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
        <Card withBorder component="section" aria-labelledby="sev-heading">
          <Title order={2} size="h4" id="sev-heading" mb="sm">
            Findings by severity
          </Title>
          {findings.total === 0 ? (
            <Text size="sm" c="dimmed">
              No findings recorded yet. Findings appear once a scan or an import produces them.
            </Text>
          ) : (
            <>
              {/* Purely visual proportion at a glance; the table below carries the real,
                  accessible counts, so this bar is hidden from assistive tech. */}
              <Progress.Root size={14} mb="md" aria-hidden="true">
                {SEVERITIES.filter((s) => findings.by_severity[s] > 0).map((s) => (
                  <Progress.Section
                    key={s}
                    value={(findings.by_severity[s] / findings.total) * 100}
                    color={SEVERITY[s].color}
                  />
                ))}
              </Progress.Root>
              <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th scope="col">Severity</Table.Th>
                  <Table.Th scope="col" ta="right">Count</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {SEVERITIES.map((s) => (
                  <Table.Tr key={s}>
                    <Table.Td>
                      <Anchor component={Link} to={`/findings?severity=${s}`} aria-label={`${s} findings`}>
                        <SeverityLabel severity={s} />
                      </Anchor>
                    </Table.Td>
                    <Table.Td ta="right">{findings.by_severity[s]}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
              </Table>
            </>
          )}
          {findings.total > 0 && (
            <Group gap="xs" mt="sm">
              {CONFIDENCES.map((c) => (
                <Anchor key={c} component={Link} to={`/findings?confidence=${c}`} size="sm">
                  {humanize(c)}: {findings.by_confidence[c]}
                </Anchor>
              ))}
            </Group>
          )}
        </Card>

        <RecentScansCard />
      </SimpleGrid>

      <Card withBorder component="section" aria-labelledby="activity-heading">
        <Group justify="space-between" mb="sm">
          <Title order={2} size="h4" id="activity-heading">
            Recent activity
          </Title>
          <Anchor component={Link} to="/audit" size="sm">
            Full audit log
          </Anchor>
        </Group>
        {data.recent_activity.length === 0 ? (
          <Text size="sm" c="dimmed">
            No activity recorded yet.
          </Text>
        ) : (
          <Stack gap={6} component="ul" style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {data.recent_activity.map((e) => (
              <li key={e.event_id}>
                <Text size="sm">
                  <strong>{humanize(e.action)}</strong>{" "}
                  <Text span c="dimmed" size="xs">
                    {formatDateTime(e.ts)}
                  </Text>
                </Text>
              </li>
            ))}
          </Stack>
        )}
      </Card>
    </Stack>
  );
}

const RECENT_SCANS_LIMIT = 5;

/** The 5 most recently updated scans across all projects (reuses the existing `/api/scans`
 * list endpoint already powering the Scans record page -- no new backend route). Shows
 * exactly what an operator needs to jump back into a scan: module, project, status, when. */
function RecentScansCard() {
  const query = useRecords<ScanJob>("scans", { limit: RECENT_SCANS_LIMIT, sort: "updated_at", order: "desc" });
  return (
    <Card withBorder component="section" aria-labelledby="recent-scans-heading">
      <Group justify="space-between" mb="sm">
        <Title order={2} size="h4" id="recent-scans-heading">
          Recent scans
        </Title>
        <Anchor component={Link} to="/scans" size="sm">
          All scans
        </Anchor>
      </Group>
      <QueryState query={query} loadingLabel="Loading recent scans…">
        {(page) =>
          page.total === 0 ? (
            <Text size="sm" c="dimmed">
              No scans have been run yet. Open a project and start one from its "Start a job" card.
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={320}>
              <Table verticalSpacing={6}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th scope="col">Scan</Table.Th>
                    <Table.Th scope="col">Module</Table.Th>
                    <Table.Th scope="col">Project</Table.Th>
                    <Table.Th scope="col">State</Table.Th>
                    <Table.Th scope="col">Updated</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {page.items.map((s) => (
                    <Table.Tr key={s.scan_id}>
                      <Table.Td>
                        <Anchor component={Link} to={`/projects/${s.project_id}/scans/${s.scan_id}`} size="sm">
                          {s.scan_id.slice(0, 12)}…
                        </Anchor>
                      </Table.Td>
                      <Table.Td>{humanize(s.module)}</Table.Td>
                      <Table.Td>{projectLink(s.project_id)}</Table.Td>
                      <Table.Td>
                        <ScanStateLabel state={s.state} />
                      </Table.Td>
                      <Table.Td>{formatDateTime(s.updated_at)}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )
        }
      </QueryState>
    </Card>
  );
}

function AuthorizationAlerts({ data }: { data: DashboardSummary }) {
  const a = data.projects.authorization;
  const items = [
    a.expired > 0 && `${a.expired} project(s) have an expired authorization window`,
    a.expiring_soon > 0 && `${a.expiring_soon} project(s) have authorization ending within 7 days`,
    a.missing > 0 && `${a.missing} project(s) have no authorization record`,
  ].filter(Boolean) as string[];
  if (items.length === 0) return null;
  return (
    <Alert color="yellow" title="Authorization attention needed" role="status">
      <Stack gap={2}>
        {items.map((i) => (
          <Text size="sm" key={i}>
            {i}
          </Text>
        ))}
        <Anchor component={Link} to="/projects" size="sm">
          Review projects
        </Anchor>
      </Stack>
    </Alert>
  );
}
