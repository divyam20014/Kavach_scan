import { Alert, Badge, Button, Card, Code, FileButton, Group, List, Stack, Table, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useApiSpecDetail, useApiSpecs, useProject, useUploadApiSpec } from "../api/hooks";
import type { ApiSpecDetail } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { formatBytes, formatDateTime } from "../lib/format";

export function ApiSpecPage() {
  const { projectId = "" } = useParams();
  const project = useProject(projectId);
  const specs = useApiSpecs(projectId);
  const upload = useUploadApiSpec(projectId);
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useApiSpecDetail(projectId, selected);

  const doUpload = (file: File | null) => {
    if (!file) return;
    upload.mutate(file, {
      onSuccess: (d: ApiSpecDetail) => {
        setSelected(d.summary.import_id);
        notifications.show({ color: "green", message: `Imported ${d.summary.operation_count} operations` });
      },
      onError: (e) => notifications.show({ color: "red", title: "Import failed", message: e instanceof ApiError ? e.describe() : "Invalid spec" }),
    });
  };

  return (
    <>
      <PageHeader
        title="API specifications"
        description={project.data?.project.name}
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Projects", to: "/projects" },
          { label: project.data?.project.name ?? "…", to: `/projects/${projectId}` }, { label: "API specs" }]}
        actions={
          <FileButton onChange={doUpload} accept=".json,.yaml,.yml,application/json,text/yaml">
            {(props) => <Button {...props} loading={upload.isPending}>Import OpenAPI / Swagger…</Button>}
          </FileButton>
        }
      />
      <Stack gap="md">
        <Text size="sm" c="dimmed">Import is offline and sends zero network requests. Supported: OpenAPI 3.0/3.1 and Swagger 2.0 (JSON or YAML).</Text>
        <QueryState query={specs} loadingLabel="Loading specs…">
          {(list) => list.length === 0 ? (
            <Card withBorder><EmptyState title="No API specs yet">Import a spec to build the operation inventory.</EmptyState></Card>
          ) : (
            <Card withBorder p={0}>
              <Table striped>
                <Table.Thead><Table.Tr>
                  <Table.Th scope="col">Spec</Table.Th><Table.Th scope="col">Type</Table.Th>
                  <Table.Th scope="col">Operations</Table.Th><Table.Th scope="col">Size</Table.Th>
                  <Table.Th scope="col">Imported</Table.Th><Table.Th scope="col" />
                </Table.Tr></Table.Thead>
                <Table.Tbody>
                  {list.map((s) => (
                    <Table.Tr key={s.import_id}>
                      <Table.Td>{s.display_filename}<Text size="xs" c="dimmed">{s.import_id.slice(0, 12)}…</Text></Table.Td>
                      <Table.Td>{s.version || s.kind}</Table.Td>
                      <Table.Td>{s.operation_count}</Table.Td>
                      <Table.Td>{formatBytes(s.size_bytes)}</Table.Td>
                      <Table.Td>{formatDateTime(s.uploaded_at)}</Table.Td>
                      <Table.Td><Button size="compact-xs" variant="light" onClick={() => setSelected(s.import_id)}>Inventory</Button></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Card>
          )}
        </QueryState>
        {selected && (
          <QueryState query={detail} loadingLabel="Loading inventory…">
            {(d) => <SpecDetail detail={d} />}
          </QueryState>
        )}
      </Stack>
    </>
  );
}

function SpecDetail({ detail }: { detail: ApiSpecDetail }) {
  const inv = detail.inventory;
  return (
    <Card withBorder component="section" aria-labelledby="inv-h">
      <Title order={2} size="h4" id="inv-h" mb="sm">{detail.summary.title} — {inv.operation_count} operations</Title>
      <Group gap="xs" mb="sm">
        <Badge variant="outline">{inv.kind} {inv.version}</Badge>
        {Object.entries(inv.security_schemes).map(([n, t]) => <Badge key={n} variant="light">{n}: {t}</Badge>)}
      </Group>
      <Title order={3} size="h6">Servers (scope-checked)</Title>
      <List size="sm" mb="sm">
        {detail.servers.map((s) => (
          <List.Item key={s.expanded}>
            <Code>{s.expanded}</Code>{" "}
            <Badge size="xs" color={s.in_scope ? "green" : "red"}>{s.in_scope ? "in scope" : "out of scope"}</Badge>
            {!s.in_scope && <Text size="xs" c="dimmed">{s.reason}</Text>}
          </List.Item>
        ))}
      </List>
      {inv.warnings.length > 0 && (
        <Alert color="yellow" variant="light" title="Import warnings" mb="sm" role="note">
          <List size="sm">{inv.warnings.map((w) => <List.Item key={w}>{w}</List.Item>)}</List>
        </Alert>
      )}
      <Table.ScrollContainer minWidth={820}>
        <Table striped aria-label="API operations">
          <Table.Thead><Table.Tr>
            <Table.Th scope="col">Operation</Table.Th><Table.Th scope="col">Auth</Table.Th>
            <Table.Th scope="col">Mutability</Table.Th><Table.Th scope="col">Parameters</Table.Th>
            <Table.Th scope="col">Request props</Table.Th>
          </Table.Tr></Table.Thead>
          <Table.Tbody>
            {inv.operations.map((o) => (
              <Table.Tr key={o.key}>
                <Table.Td><Code>{o.method}</Code> {o.path}<Text size="xs" c="dimmed">{o.op_id}{o.tags.length ? ` · ${o.tags.join(", ")}` : ""}</Text></Table.Td>
                <Table.Td>{o.security_required ? (o.auth_schemes.join(", ") || "required") : "none"}</Table.Td>
                <Table.Td><Badge size="xs" color={o.mutating ? "orange" : "gray"} variant="outline">{o.mutating ? "mutating" : "read-only"}</Badge></Table.Td>
                <Table.Td>{o.parameters.map((p) => `${p.name} (${p.location})`).join(", ") || "—"}</Table.Td>
                <Table.Td>{o.request_schema_props.join(", ") || "—"}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Card>
  );
}
