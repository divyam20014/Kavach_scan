import { Anchor, Button, Card, Group, Pagination, Select, Stack, Table, Text, TextInput } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useProjects } from "../api/hooks";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { AuthorizationLabel, ProjectStatusLabel, ScanStateLabel } from "../components/StatusLabel";
import { formatDateTime } from "../lib/format";

const PAGE_SIZE = 20;

export function ProjectsPage() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [debounced] = useDebouncedValue(search, 250);
  const status = params.get("status") ?? "";
  const sort = params.get("sort") ?? "updated_at";
  const page = Math.max(1, Number(params.get("page") ?? "1"));

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("page" in patch)) next.delete("page");
    setParams(next, { replace: true });
  };

  const query = useProjects({
    q: debounced || undefined,
    status: status || undefined,
    sort,
    order: sort === "name" ? "asc" : "desc",
    offset: (page - 1) * PAGE_SIZE,
    limit: PAGE_SIZE,
  });
  // VAPT mode excludes repository-scan-only projects (TBD-116) -- a project whose
  // allowed_modules is exactly ["repo_scan"] was created from the separate Repository
  // Scan flow and belongs there, not in this list. Filters the current page client-side;
  // `total`/pagination still reflect the server's unfiltered count (no backend change for
  // this), an accepted, disclosed simplification at this app's single-operator scale.
  const isRepoOnly = (modules: string[]) => modules.length === 1 && modules[0] === "repo_scan";

  return (
    <>
      <PageHeader
        title="Projects"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Projects" }]}
        actions={
          <Button component={Link} to="/projects/new">
            New project
          </Button>
        }
      />
      <Card withBorder mb="md">
        <Group align="flex-end" wrap="wrap">
          <TextInput
            label="Search"
            placeholder="Project or client name"
            value={search}
            onChange={(e) => {
              setSearch(e.currentTarget.value);
              update({ q: e.currentTarget.value });
            }}
            w={260}
          />
          <Select
            label="Status"
            data={[
              { value: "", label: "All" },
              { value: "active", label: "Active" },
              { value: "archived", label: "Archived" },
            ]}
            value={status}
            onChange={(v) => update({ status: v ?? "" })}
            allowDeselect={false}
            w={160}
          />
          <Select
            label="Sort by"
            data={[
              { value: "updated_at", label: "Last updated" },
              { value: "created_at", label: "Created" },
              { value: "name", label: "Name" },
            ]}
            value={sort}
            onChange={(v) => update({ sort: v ?? "updated_at" })}
            allowDeselect={false}
            w={180}
          />
        </Group>
      </Card>

      <QueryState query={query} loadingLabel="Loading projects…">
        {(raw) => {
          const data = { ...raw, items: raw.items.filter((o) => !isRepoOnly(o.project.scan_policy.allowed_modules)) };
          return data.items.length === 0 ? (
            <Card withBorder>
              <EmptyState
                title={debounced || status ? "No projects match these filters" : "No projects yet"}
                action={
                  !(debounced || status) && (
                    <Button component={Link} to="/projects/new">
                      Create your first project
                    </Button>
                  )
                }
              >
                {debounced || status ? "Try a different search or status filter." : "A project holds the authorization record, scope and limits for an assessment."}
              </EmptyState>
            </Card>
          ) : (
            <Stack>
              {data.errors.length > 0 && (
                <Text size="sm" c="orange.8" role="status">
                  {data.errors.length} project record(s) could not be read and are not shown.
                </Text>
              )}
              <Card withBorder p={0}>
                <Table.ScrollContainer minWidth={760}>
                  <Table striped highlightOnHover>
                    <Table.Caption>
                      {data.items.length} project(s)
                    </Table.Caption>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th scope="col">Project</Table.Th>
                        <Table.Th scope="col">Client</Table.Th>
                        <Table.Th scope="col">Status</Table.Th>
                        <Table.Th scope="col">Authorization</Table.Th>
                        <Table.Th scope="col">Last scan</Table.Th>
                        <Table.Th scope="col">Updated</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {data.items.map(({ project, authorization_status, authorization_expires_at, last_scan }) => (
                        <Table.Tr key={project.project_id}>
                          <Table.Td>
                            <Anchor component={Link} to={`/projects/${project.project_id}`} fw={600}>
                              {project.name}
                            </Anchor>
                          </Table.Td>
                          <Table.Td>{project.client_name}</Table.Td>
                          <Table.Td>
                            <ProjectStatusLabel status={project.status} />
                          </Table.Td>
                          <Table.Td>
                            <Stack gap={2}>
                              <AuthorizationLabel status={authorization_status} />
                              {authorization_expires_at && (
                                <Text size="xs" c="dimmed">
                                  Ends {formatDateTime(authorization_expires_at)}
                                </Text>
                              )}
                            </Stack>
                          </Table.Td>
                          <Table.Td>
                            {last_scan ? <ScanStateLabel state={last_scan.state} /> : <Text size="sm" c="dimmed">Never</Text>}
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm">{formatDateTime(project.updated_at)}</Text>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              </Card>
              {data.total > PAGE_SIZE && (
                <Pagination
                  total={Math.ceil(data.total / PAGE_SIZE)}
                  value={page}
                  onChange={(p) => update({ page: String(p) })}
                  aria-label="Projects pages"
                />
              )}
            </Stack>
          );
        }}
      </QueryState>
    </>
  );
}
