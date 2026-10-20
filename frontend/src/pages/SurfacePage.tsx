import { Badge, Button, Card, Group, Menu, Select, Stack, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useApproveAsset, useProject, useSetCriticality, useSurface } from "../api/hooks";
import type { SurfaceAsset } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { formatDateTime, humanize } from "../lib/format";

const CRITICALITY = ["low", "medium", "high", "critical"];

export function SurfacePage() {
  const { projectId = "" } = useParams();
  const project = useProject(projectId);
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const q = params.get("q") ?? "";
  const sort = params.get("sort") ?? "priority";
  const surface = useSurface(projectId, { status: status || undefined, q: q || undefined, sort });
  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next);
  };

  return (
    <>
      <PageHeader
        title="Attack surface"
        description={project.data ? `${project.data.project.name}` : undefined}
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Projects", to: "/projects" },
          { label: project.data?.project.name ?? "…", to: `/projects/${projectId}` }, { label: "Attack surface" }]}
      />
      <Stack gap="md">
        <Group>
          <TextInput aria-label="Filter by locator" placeholder="Filter by name…" value={q}
            onChange={(e) => setParam("q", e.currentTarget.value)} />
          <Select aria-label="Status filter" placeholder="All statuses" clearable value={status || null}
            onChange={(v) => setParam("status", v ?? "")}
            data={["in_scope", "pending_approval", "out_of_scope", "excluded", "unresolved"].map((s) => ({ value: s, label: humanize(s) }))} />
          <Select aria-label="Sort" value={sort} onChange={(v) => setParam("sort", v ?? "priority")}
            data={[{ value: "priority", label: "Priority" }, { value: "last_seen", label: "Last seen" }, { value: "locator", label: "Name" }]} />
        </Group>
        <QueryState query={surface} loadingLabel="Loading asset graph…">
          {(view) => view.total === 0 ? (
            <Card withBorder><EmptyState title="No assets yet">Run an attack-surface scan from the project page to build the inventory.</EmptyState></Card>
          ) : (
            <Stack gap="sm">
              <Group gap="xs">
                {Object.entries(view.counts.type).map(([t, n]) => <Badge key={t} variant="light">{humanize(t)}: {n}</Badge>)}
              </Group>
              <Card withBorder p={0}>
                <Table.ScrollContainer minWidth={820}>
                  <Table striped>
                    <Table.Caption>{view.total} asset(s){view.truncated ? " (showing first 5000)" : ""}</Table.Caption>
                    <Table.Thead><Table.Tr>
                      <Table.Th scope="col">Asset</Table.Th><Table.Th scope="col">Type</Table.Th>
                      <Table.Th scope="col">Status</Table.Th><Table.Th scope="col">Priority</Table.Th>
                      <Table.Th scope="col">Criticality</Table.Th><Table.Th scope="col">Last seen</Table.Th>
                    </Table.Tr></Table.Thead>
                    <Table.Tbody>
                      {view.items.map((row) => <AssetRow key={row.asset.asset_id} projectId={projectId}
                        row={row} projectRevision={project.data?.project.revision ?? 1} />)}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              </Card>
            </Stack>
          )}
        </QueryState>
      </Stack>
    </>
  );
}

function AssetRow({ projectId, row, projectRevision }: { projectId: string; row: SurfaceAsset; projectRevision: number }) {
  const { asset } = row;
  const setCrit = useSetCriticality(projectId);
  const approve = useApproveAsset(projectId);
  const [open, setOpen] = useState(false);
  return (
    <Table.Tr>
      <Table.Td style={{ wordBreak: "break-all" }}>
        {asset.locator}
        {asset.attributes?.service != null && <Text size="xs" c="dimmed">{String(asset.attributes.service)} {String(asset.attributes.version ?? "")}</Text>}
      </Table.Td>
      <Table.Td>{humanize(asset.asset_type)}</Table.Td>
      <Table.Td>
        <Badge variant="outline" color={row.candidate_status === "in_scope" ? "green" : row.candidate_status === "pending_approval" ? "yellow" : "gray"}>
          {humanize(row.candidate_status)}
        </Badge>
        {row.candidate_status === "pending_approval" && asset.asset_type === "hostname" && (
          <Button size="compact-xs" variant="light" ml={6} loading={approve.isPending} onClick={() =>
            approve.mutate({ assetId: asset.asset_id, expectedProjectRevision: projectRevision }, {
              onSuccess: () => notifications.show({ color: "green", message: `${asset.locator} added to scope` }),
              onError: (e) => notifications.show({ color: "red", message: e instanceof ApiError ? e.describe() : "Approve failed" }),
            })}>Approve</Button>
        )}
      </Table.Td>
      <Table.Td>
        <Tooltip multiline w={280} label={row.priority_factors.join("\n")} events={{ hover: true, focus: true, touch: true }}>
          <Badge variant={row.priority > 0 ? "filled" : "default"} color={row.priority >= 30 ? "red" : row.priority >= 10 ? "orange" : "gray"}>{row.priority}</Badge>
        </Tooltip>
        {row.findings > 0 && <Text span size="xs" c="dimmed" ml={4}>{row.findings} finding(s)</Text>}
      </Table.Td>
      <Table.Td>
        <Menu opened={open} onChange={setOpen}>
          <Menu.Target><Button size="compact-xs" variant="default">{asset.criticality ?? "set…"}</Button></Menu.Target>
          <Menu.Dropdown>
            {CRITICALITY.map((c) => <Menu.Item key={c} onClick={() => setCrit.mutate({ assetId: asset.asset_id, expectedRevision: asset.revision ?? 1, criticality: c })}>{c}</Menu.Item>)}
            <Menu.Item onClick={() => setCrit.mutate({ assetId: asset.asset_id, expectedRevision: asset.revision ?? 1, criticality: null })}>clear</Menu.Item>
          </Menu.Dropdown>
        </Menu>
      </Table.Td>
      <Table.Td>{formatDateTime(asset.last_seen)}</Table.Td>
    </Table.Tr>
  );
}
