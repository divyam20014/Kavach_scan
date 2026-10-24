import { Alert, Badge, Button, Card, FileButton, Group, List, Stack, Table, Text, Textarea, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useCommitImport, useImportDetail, useImportFormats, useImports, useProject, useUploadImport } from "../api/hooks";
import type { ImportDetail, ImportSummary } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { formatBytes, formatDateTime } from "../lib/format";

export function ImportsPage() {
  const { projectId = "" } = useParams();
  const project = useProject(projectId);
  const formats = useImportFormats();
  const imports = useImports(projectId);
  const upload = useUploadImport(projectId);
  const [selected, setSelected] = useState<string | null>(null);
  const [columnMap, setColumnMap] = useState("");
  const detail = useImportDetail(projectId, selected);

  const doUpload = (file: File | null) => {
    if (!file) return;
    let optionsJson: string | undefined;
    if (columnMap.trim()) {
      try {
        JSON.parse(columnMap); // validate before sending
        optionsJson = columnMap;
      } catch {
        notifications.show({ color: "red", title: "Invalid mapping", message: "Column/field map must be valid JSON" });
        return;
      }
    }
    upload.mutate(
      { file, optionsJson },
      {
        onSuccess: (d: ImportDetail) => {
          setSelected(d.summary.import_id);
          if (d.error) {
            notifications.show({ color: "red", title: "Could not parse file", message: d.error });
          } else {
            notifications.show({ color: "green", message: `Parsed ${d.preview?.parsed_count ?? 0} record(s) — review before committing` });
          }
        },
        onError: (e) => notifications.show({ color: "red", title: "Upload failed", message: e instanceof ApiError ? e.describe() : "Upload failed" }),
      },
    );
  };

  return (
    <>
      <PageHeader
        title="Import Center"
        description={project.data?.project.name}
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Projects", to: "/projects" },
          { label: project.data?.project.name ?? "…", to: `/projects/${projectId}` }, { label: "Imports" }]}
        actions={
          <FileButton onChange={doUpload} accept=".xml,.json,.jsonl,.ndjson,.csv,.tsv,.sarif,.nessus,.pdf,.zip">
            {(props) => <Button {...props} loading={upload.isPending}>Upload report…</Button>}
          </FileButton>
        }
      />
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Upload is offline and parses the file only; nothing is added to this project&apos;s findings
          until you explicitly commit an import below.
        </Text>
        <QueryState query={formats} loadingLabel="Loading supported formats…">
          {(f) => (
            <Card withBorder>
              <Title order={3} size="h6" mb="xs">Supported formats</Title>
              <Group gap="xs" mb="sm">
                {f.supported.map((s) => <Badge key={s.source_type} variant="light">{s.label}</Badge>)}
              </Group>
              {f.unsupported.length > 0 && (
                <>
                  <Title order={4} size="h6" mb="xs">Not supported this release</Title>
                  <List size="sm" c="dimmed">
                    {f.unsupported.map((u) => <List.Item key={u.source_type}><b>{u.source_type}</b>: {u.reason}</List.Item>)}
                  </List>
                </>
              )}
              <Textarea
                mt="sm" label="Optional column/field map (generic CSV or JSON only)"
                description='e.g. {"column_map": {"title": "Vulnerability Name"}} or {"field_map": {"title": "name"}}'
                placeholder='{"column_map": {"title": "Your Header"}}'
                value={columnMap} onChange={(e) => setColumnMap(e.currentTarget.value)}
                autosize minRows={1}
              />
            </Card>
          )}
        </QueryState>
        <QueryState query={imports} loadingLabel="Loading imports…">
          {(list) => list.length === 0 ? (
            <Card withBorder><EmptyState title="No imports yet">Upload a report to see a dry-run preview.</EmptyState></Card>
          ) : (
            <Card withBorder p={0}>
              <Table striped>
                <Table.Thead><Table.Tr>
                  <Table.Th scope="col">File</Table.Th><Table.Th scope="col">Format</Table.Th>
                  <Table.Th scope="col">Status</Table.Th><Table.Th scope="col">Records</Table.Th>
                  <Table.Th scope="col">Size</Table.Th><Table.Th scope="col">Uploaded</Table.Th>
                  <Table.Th scope="col" />
                </Table.Tr></Table.Thead>
                <Table.Tbody>
                  {list.map((s: ImportSummary) => (
                    <Table.Tr key={s.import_id}>
                      <Table.Td>{s.display_filename}<Text size="xs" c="dimmed">{s.import_id.slice(0, 12)}…</Text></Table.Td>
                      <Table.Td>{s.source_type}</Table.Td>
                      <Table.Td><Badge size="xs" color={statusColor(s.status)}>{s.status}</Badge></Table.Td>
                      <Table.Td>{s.record_count} parsed{s.rejected_count ? `, ${s.rejected_count} rejected` : ""}</Table.Td>
                      <Table.Td>{formatBytes(s.size_bytes)}</Table.Td>
                      <Table.Td>{formatDateTime(s.uploaded_at)}</Table.Td>
                      <Table.Td><Button size="compact-xs" variant="light" onClick={() => setSelected(s.import_id)}>Review</Button></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Card>
          )}
        </QueryState>
        {selected && (
          <QueryState query={detail} loadingLabel="Loading preview…">
            {(d) => <ImportReview projectId={projectId} detail={d} />}
          </QueryState>
        )}
      </Stack>
    </>
  );
}

function statusColor(status: string): string {
  if (status === "committed") return "green";
  if (status === "parse_failed" || status === "rejected") return "red";
  return "blue";
}

function ImportReview({ projectId, detail }: { projectId: string; detail: ImportDetail }) {
  const commit = useCommitImport(projectId);
  const { summary, preview, error } = detail;
  const committed = summary.status === "committed";

  const doCommit = () => {
    commit.mutate(
      { importId: summary.import_id, expectedRevision: summary.revision },
      {
        onSuccess: (res) => notifications.show({
          color: "green",
          message: `Committed: ${res.findings_created} new finding(s), ${res.findings_reobserved} re-observed, ${res.assets_created} new asset(s)`,
        }),
        onError: (e) => notifications.show({ color: "red", title: "Commit failed", message: e instanceof ApiError ? e.describe() : "Commit failed" }),
      },
    );
  };

  if (error) {
    return (
      <Alert color="red" title="Could not parse this file" role="alert">
        {error}
      </Alert>
    );
  }
  if (!preview) return null;

  return (
    <Card withBorder component="section" aria-labelledby="import-review-h">
      <Group justify="space-between" mb="sm">
        <Title order={2} size="h4" id="import-review-h">
          {preview.label} — {preview.parsed_count} parsed, {preview.rejected_count} rejected
        </Title>
        <Button onClick={doCommit} loading={commit.isPending} disabled={committed} color={committed ? "gray" : "blue"}>
          {committed ? "Already committed" : "Commit to project"}
        </Button>
      </Group>
      <Text size="sm" c="dimmed" mb="sm">
        Source tool: {preview.source_tool_version || "unknown"} · Parser: {preview.parser_version} ·
        {" "}{preview.asset_count} asset(s) will be inventoried.
      </Text>
      {preview.mapping_gaps.length > 0 && (
        <Alert color="yellow" variant="light" title="Mapping gaps" mb="sm" role="note">
          No column/field matched for: {preview.mapping_gaps.join(", ")}. These will be empty or default on every imported record — use the column/field map above if your export uses different names.
        </Alert>
      )}
      {preview.warnings.length > 0 && (
        <Alert color="yellow" variant="light" title="Parser warnings" mb="sm" role="note">
          <List size="sm">{preview.warnings.slice(0, 50).map((w, i) => <List.Item key={i}>{w}</List.Item>)}</List>
        </Alert>
      )}
      {preview.duplicate_candidates.length > 0 && (
        <Alert color="orange" variant="light" title="Possible duplicates (title match only — review before committing)" mb="sm" role="note">
          <List size="sm">
            {preview.duplicate_candidates.map((c, i) => (
              <List.Item key={i}>
                &quot;{c.title}&quot;{c.existing_finding_id ? " matches an existing finding by title only" : " appears more than once in this file"}
              </List.Item>
            ))}
          </List>
        </Alert>
      )}
      {preview.truncated_sample && (
        <Text size="xs" c="dimmed" mb="sm">Showing the first {preview.records.length} of {preview.parsed_count} records.</Text>
      )}
      <Table.ScrollContainer minWidth={760}>
        <Table striped aria-label="Parsed findings preview">
          <Table.Thead><Table.Tr>
            <Table.Th scope="col">Title</Table.Th><Table.Th scope="col">Severity</Table.Th>
            <Table.Th scope="col">Confidence</Table.Th><Table.Th scope="col">Host/URL</Table.Th>
            <Table.Th scope="col">Action</Table.Th>
          </Table.Tr></Table.Thead>
          <Table.Tbody>
            {preview.records.map((r) => (
              <Table.Tr key={r.index}>
                <Table.Td>{r.title}</Table.Td>
                <Table.Td><Badge size="xs" variant="outline">{r.severity}</Badge></Table.Td>
                <Table.Td>{r.confidence}</Table.Td>
                <Table.Td>{r.url ?? r.host ?? "—"}</Table.Td>
                <Table.Td>
                  <Badge size="xs" color={r.action === "new" ? "blue" : "gray"}>
                    {r.action === "update_existing" && "re-observe existing"}
                    {r.action === "duplicate_in_import" && `duplicate of row ${(r.duplicate_of_index ?? 0) + 1} in this file`}
                    {r.action === "new" && "new finding"}
                  </Badge>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Card>
  );
}
