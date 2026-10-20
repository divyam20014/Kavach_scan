import { Alert, Anchor, Button, Card, Code, Group, List, Pagination, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAudit, useStorageDiagnostics, useVersion } from "../api/hooks";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { NotConfiguredLabel } from "../components/StatusLabel";
import { formatBytes, formatDateTime, humanize } from "../lib/format";

export function AuditPage() {
  const [page, setPage] = useState(1);
  const limit = 50;
  const audit = useAudit({ offset: (page - 1) * limit, limit });
  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only record of operator actions. Secret-looking values are redacted before they are written."
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Audit log" }]}
      />
      <QueryState query={audit}>
        {(data) =>
          data.items.length === 0 ? (
            <Card withBorder>
              <EmptyState title="No audit events" />
            </Card>
          ) : (
            <Stack>
              {data.corrupt_lines > 0 && (
                <Alert color="yellow" role="status">
                  {data.corrupt_lines} unreadable log line(s) were skipped.
                </Alert>
              )}
              <Card withBorder p={0}>
                <Table.ScrollContainer minWidth={760}>
                  <Table striped>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th scope="col">Time</Table.Th>
                        <Table.Th scope="col">Action</Table.Th>
                        <Table.Th scope="col">Outcome</Table.Th>
                        <Table.Th scope="col">Project</Table.Th>
                        <Table.Th scope="col">Details</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {data.items.map((e) => (
                        <Table.Tr key={e.event_id}>
                          <Table.Td>{formatDateTime(e.ts)}</Table.Td>
                          <Table.Td>{humanize(e.action)}</Table.Td>
                          <Table.Td>{humanize(e.outcome)}</Table.Td>
                          <Table.Td>
                            {e.project_id ? (
                              <Anchor component={Link} to={`/projects/${e.project_id}`} size="sm">
                                {e.project_id.slice(0, 12)}…
                              </Anchor>
                            ) : (
                              "—"
                            )}
                          </Table.Td>
                          <Table.Td>
                            {/* Rendered as escaped text only; never as HTML. */}
                            <Code style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{JSON.stringify(e.metadata)}</Code>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              </Card>
              <Pagination total={page + (data.has_more ? 1 : 0)} value={page} onChange={setPage} aria-label="Audit pages" />
            </Stack>
          )
        }
      </QueryState>
    </>
  );
}

export function SettingsPage() {
  const version = useVersion();
  const diagnostics = useStorageDiagnostics();
  return (
    <>
      <PageHeader title="Settings & storage" crumbs={[{ label: "Dashboard", to: "/" }, { label: "Settings & storage" }]} />
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder component="section" aria-labelledby="ver-h">
          <Title order={2} size="h4" id="ver-h" mb="sm">
            Application
          </Title>
          <QueryState query={version}>
            {(v) => (
              <Table variant="vertical">
                <Table.Tbody>
                  <Table.Tr><Table.Th>Version</Table.Th><Table.Td>{v.version}</Table.Td></Table.Tr>
                  <Table.Tr><Table.Th>API version</Table.Th><Table.Td>{v.api_version}</Table.Td></Table.Tr>
                  <Table.Tr><Table.Th>Storage format</Table.Th><Table.Td>v{v.storage_version}</Table.Td></Table.Tr>
                  <Table.Tr><Table.Th>Python</Table.Th><Table.Td>{v.python}</Table.Td></Table.Tr>
                  <Table.Tr>
                    <Table.Th>Scanning</Table.Th>
                    <Table.Td>{v.scanning_available ? "Available" : <NotConfiguredLabel>Not available in this build</NotConfiguredLabel>}</Table.Td>
                  </Table.Tr>
                </Table.Tbody>
              </Table>
            )}
          </QueryState>
        </Card>

        <Card withBorder component="section" aria-labelledby="data-h">
          <Group justify="space-between" mb="sm">
            <Title order={2} size="h4" id="data-h">
              Data directory
            </Title>
            <Button size="xs" variant="default" onClick={() => void diagnostics.refetch()} loading={diagnostics.isFetching}>
              Refresh
            </Button>
          </Group>
          <QueryState query={diagnostics}>
            {(d) => (
              <Stack gap="xs">
                <Table variant="vertical">
                  <Table.Tbody>
                    <Table.Tr><Table.Th>Location</Table.Th><Table.Td><Code>{d.storage.data_dir}</Code></Table.Td></Table.Tr>
                    <Table.Tr><Table.Th>Status</Table.Th><Table.Td>{d.storage.ready ? "✓ Ready" : "✕ Not ready"}</Table.Td></Table.Tr>
                    <Table.Tr><Table.Th>Writable</Table.Th><Table.Td>{d.storage.writable ? "Yes" : "No"}</Table.Td></Table.Tr>
                    <Table.Tr><Table.Th>Free space</Table.Th><Table.Td>{formatBytes(d.storage.free_bytes)} of {formatBytes(d.storage.total_bytes)}{d.storage.low_disk_space ? " — low" : ""}</Table.Td></Table.Tr>
                    <Table.Tr><Table.Th>Instance lock</Table.Th><Table.Td>{humanize(d.storage.instance_lock)}</Table.Td></Table.Tr>
                    <Table.Tr><Table.Th>Last integrity check</Table.Th><Table.Td>{d.last_integrity_check ? `${formatDateTime(d.last_integrity_check.checked_at)} — ${d.last_integrity_check.issues.length} issue(s)` : "Not run"}</Table.Td></Table.Tr>
                  </Table.Tbody>
                </Table>
                {d.storage.warnings.map((w) => (
                  <Alert key={w} color="yellow" role="status">{w}</Alert>
                ))}
                {d.last_integrity_check?.issues.slice(0, 10).map((i) => (
                  <Text size="sm" key={`${i.kind}-${i.location}`}>! {humanize(i.kind)}: {i.message} <Code>{i.location}</Code></Text>
                ))}
              </Stack>
            )}
          </QueryState>
        </Card>

        <Card withBorder component="section" aria-labelledby="tools-h">
          <Title order={2} size="h4" id="tools-h" mb="sm">
            External tools
          </Title>
          <Text size="sm">
            Tool detection for Nmap, sslyze and testssl.sh is implemented in Phase 11. Until then no tool is checked, so none is reported as available.
          </Text>
        </Card>
      </SimpleGrid>
    </>
  );
}

export function HelpPage() {
  return (
    <>
      <PageHeader title="Help & limitations" crumbs={[{ label: "Dashboard", to: "/" }, { label: "Help & limitations" }]} />
      <Card withBorder>
        <Stack gap="sm">
          <Title order={2} size="h4">What this build can do</Title>
          <List size="sm">
            <List.Item>Create, edit, archive and delete projects with an authorization record, scope and request limits.</List.Item>
            <List.Item>Preview and normalize scope entries (hostnames, wildcards, IP ranges, URLs, ports, paths).</List.Item>
            <List.Item>Show dashboard counts and lists computed from stored records, plus the audit log.</List.Item>
          </List>
          <Title order={2} size="h4">What it cannot do yet</Title>
          <List size="sm">
            <List.Item>Run any scan. Scope enforcement (Phase 03), the job manager (Phase 04) and scanners (Phases 05–07) are not built.</List.Item>
            <List.Item>Import external reports (Phase 08), generate reports (Phase 10), or detect external tools (Phase 11).</List.Item>
          </List>
          <Title order={2} size="h4">Safe use</Title>
          <Text size="sm">
            Only test systems you are explicitly authorized to test. The attestation checkbox records your statement; it is not legal verification.
            The application binds to this computer only (127.0.0.1) and stores data in your user profile, not in the source folder.
          </Text>
        </Stack>
      </Card>
    </>
  );
}

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="This page does not exist" action={<Anchor component={Link} to="/">Back to the dashboard</Anchor>} />
    </>
  );
}
