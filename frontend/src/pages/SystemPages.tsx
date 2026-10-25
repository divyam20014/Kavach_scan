import { Alert, Anchor, Button, Card, Checkbox, Code, FileButton, Group, List, Pagination, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api/client";
import { useAudit, useBackupPreview, useBackupRestore, useStorageDiagnostics, useVersion } from "../api/hooks";
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
            External tools &amp; CVE catalog
          </Title>
          <Text size="sm" c="dimmed" mb="sm">
            Nmap, sslyze/testssl.sh and the local CVE catalog are optional. Missing tools
            degrade to built-in fallbacks or skipped checks — never a false pass.
          </Text>
          <Anchor component={Link} to="/integrations">
            Open Integrations &amp; CVE catalog
          </Anchor>
        </Card>

        <BackupRestoreCard />
      </SimpleGrid>
    </>
  );
}

function BackupRestoreCard() {
  const preview = useBackupPreview();
  const restore = useBackupRestore();
  const [file, setFile] = useState<File | null>(null);
  const [overwrite, setOverwrite] = useState(false);

  const onFile = (f: File | null) => {
    setFile(f);
    preview.reset();
    if (!f) return;
    preview.mutate(f, {
      onError: (e) => notifications.show({ color: "red", title: "Could not read archive", message: e instanceof ApiError ? e.describe() : "Invalid archive" }),
    });
  };

  const doRestore = () => {
    if (!file) return;
    restore.mutate(
      { file, confirmed: true, overwrite },
      {
        onSuccess: (r) => {
          notifications.show({ color: "green", message: `Restored project ${r.project_id.slice(0, 12)}… (${r.counts.findings} finding(s))` });
          setFile(null);
          preview.reset();
        },
        onError: (e) => notifications.show({ color: "red", title: "Restore failed", message: e instanceof ApiError ? e.describe() : "Restore failed" }),
      },
    );
  };

  return (
    <Card withBorder component="section" aria-labelledby="backup-h">
      <Title order={2} size="h4" id="backup-h" mb="sm">
        Backup &amp; restore
      </Title>
      <Text size="sm" c="dimmed" mb="sm">
        Export a full project backup from its page (Reports). Restoring always previews the
        archive first and never overwrites existing data unless explicitly confirmed.
      </Text>
      <FileButton onChange={onFile} accept="application/zip,.zip">
        {(props) => <Button {...props} variant="default" loading={preview.isPending}>Choose backup archive…</Button>}
      </FileButton>
      {preview.data && (
        <Stack gap="xs" mt="sm">
          <Text size="sm">
            <strong>{preview.data.project_name}</strong> ({preview.data.project_id.slice(0, 12)}…) —
            exported {formatDateTime(preview.data.exported_at)}
          </Text>
          <Group gap="xs">
            {Object.entries(preview.data.counts).map(([k, v]) => (
              <Code key={k}>{k}: {v}</Code>
            ))}
          </Group>
          {preview.data.checksum_mismatches.length > 0 && (
            <Alert color="red" role="alert" title="Checksum mismatch">
              This archive failed integrity verification and cannot be restored.
            </Alert>
          )}
          {preview.data.warnings.map((w) => <Alert key={w} color="yellow" role="status">{w}</Alert>)}
          {preview.data.project_already_exists && (
            <>
              <Alert color="yellow" role="status">
                A project with this id already exists. Restoring will replace it only if you confirm below.
              </Alert>
              <Checkbox label="Overwrite the existing project" checked={overwrite} onChange={(e) => setOverwrite(e.currentTarget.checked)} />
            </>
          )}
          <Button
            onClick={doRestore} loading={restore.isPending}
            disabled={preview.data.checksum_mismatches.length > 0 || (preview.data.project_already_exists && !overwrite)}
            w="fit-content"
          >
            Restore
          </Button>
        </Stack>
      )}
    </Card>
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
            <List.Item>Preview and normalize scope entries, check any URL against a project's scope, and manage audited internal-target overrides.</List.Item>
            <List.Item>Run the web application scanner (safe mode), the attack-surface mapper, and the API security scanner, all gated by scope and authorization.</List.Item>
            <List.Item>Import external scanner/VAPT reports (Nmap, Nessus, Nuclei, SARIF, generic CSV/JSON, best-effort PDF), with a dry-run preview before anything is merged.</List.Item>
            <List.Item>Triage findings in a central workbench: search/filter/sort, comments, business priority, manual merge/unmerge, and an internal (non-CVSS) risk score.</List.Item>
            <List.Item>Build and download an HTML/PDF report, export findings/assets as JSON/CSV, and export/restore a full project backup archive.</List.Item>
            <List.Item>Show dashboard counts and lists computed from stored records, plus the audit log.</List.Item>
          </List>
          <Title order={2} size="h4">What it cannot do yet</Title>
          <List size="sm">
            <List.Item>Detect or run external tools such as Nmap, sslyze or testssl.sh binaries (Phase 11) — scans run in safe/degraded mode without them.</List.Item>
            <List.Item>Import ZAP or Burp exports directly (use the generic CSV/JSON import with a column/field map instead).</List.Item>
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
