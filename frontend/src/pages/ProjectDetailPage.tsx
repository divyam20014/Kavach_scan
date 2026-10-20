import { Alert, Anchor, Badge, Button, Card, Code, Group, List, Modal, SimpleGrid, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useAudit, useDeleteProject, useDeletionImpact, useProject, useUpdateProject } from "../api/hooks";
import type { ProjectOverview, ScopeDefinition } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ErrorAlert, Loading, QueryState } from "../components/QueryState";
import { AuthorizationLabel, ProjectStatusLabel, ScanStateLabel } from "../components/StatusLabel";
import { formatDateTime, humanize } from "../lib/format";

export function ProjectDetailPage() {
  const { projectId = "" } = useParams();
  const query = useProject(projectId);
  return (
    <QueryState query={query} loadingLabel="Loading project…">
      {(data) => <ProjectDetail overview={data} />}
    </QueryState>
  );
}

function ProjectDetail({ overview }: { overview: ProjectOverview }) {
  const { project, counts, authorization_status, last_scan } = overview;
  const update = useUpdateProject(project.project_id);
  const [deleting, setDeleting] = useState(false);
  const archived = project.status === "archived";

  const toggleArchive = () =>
    update.mutate(
      { expected_revision: project.revision, status: archived ? "active" : "archived" },
      {
        onSuccess: () => notifications.show({ color: "green", message: archived ? "Project restored" : "Project archived" }),
        onError: (e) => notifications.show({ color: "red", title: "Update failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
      },
    );

  return (
    <>
      <PageHeader
        title={project.name}
        description={`Client: ${project.client_name}`}
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Projects", to: "/projects" }, { label: project.name }]}
        actions={
          <>
            <Button component={Link} to={`/projects/${project.project_id}/edit`} variant="default">
              Edit
            </Button>
            <Button variant="default" onClick={toggleArchive} loading={update.isPending}>
              {archived ? "Restore" : "Archive"}
            </Button>
            <Button color="red" variant="light" onClick={() => setDeleting(true)}>
              Delete…
            </Button>
          </>
        }
      />
      <Stack gap="md">
        <Group gap="sm">
          <ProjectStatusLabel status={project.status} />
          <AuthorizationLabel status={authorization_status} />
          <Badge variant="outline" color="gray">
            Revision {project.revision}
          </Badge>
        </Group>

        <Alert role="note" color="gray" title="Scanning is not available in this build" variant="light">
          Scans require the scope engine (Phase 03) and job manager (Phase 04). This page shows stored project data only.
        </Alert>

        <SimpleGrid cols={{ base: 2, sm: 3, md: 6 }}>
          {(["scan", "finding", "asset", "evidence", "import", "report"] as const).map((k) => (
            <Card withBorder key={k} padding="sm">
              <Text size="xs" c="dimmed">
                {humanize(k)}s
              </Text>
              <Text fw={700} fz="xl">
                {counts[k]}
              </Text>
            </Card>
          ))}
        </SimpleGrid>

        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <Card withBorder component="section" aria-labelledby="auth-h">
            <Title order={2} size="h4" id="auth-h" mb="sm">
              Authorization
            </Title>
            {project.authorization ? (
              <Table variant="vertical" layout="fixed">
                <Table.Tbody>
                  <Row label="Organization" value={project.authorization.organization} />
                  <Row label="Target owner" value={project.authorization.target_owner} />
                  <Row label="Authorized by" value={project.authorization.authorized_by} />
                  <Row label="Reference" value={project.authorization.reference || "—"} />
                  <Row label="Window start" value={formatDateTime(project.authorization.window_start)} />
                  <Row label="Window end" value={formatDateTime(project.authorization.window_end)} />
                  <Row label="Attestation" value={project.authorization.attestation_event_id ? `Recorded (${project.authorization.attestation_event_id})` : "Not recorded"} />
                </Table.Tbody>
              </Table>
            ) : (
              <Text size="sm" c="dimmed">
                No authorization recorded. Add one by editing the project before any future scanning.
              </Text>
            )}
          </Card>
          <Card withBorder component="section" aria-labelledby="scope-h">
            <Title order={2} size="h4" id="scope-h" mb="sm">
              Scope (stored, not yet enforced)
            </Title>
            <ScopeSummary scope={project.scope} />
          </Card>
        </SimpleGrid>

        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <Card withBorder component="section" aria-labelledby="limits-h">
            <Title order={2} size="h4" id="limits-h" mb="sm">
              Allowed modules & limits
            </Title>
            <Text size="sm">
              Modules: {project.scan_policy.allowed_modules.length ? project.scan_policy.allowed_modules.map(humanize).join(", ") : "none selected"}
            </Text>
            <Text size="sm">
              {project.scan_policy.requests_per_second} req/s · concurrency {project.scan_policy.max_concurrency} · max{" "}
              {project.scan_policy.max_pages} pages · depth {project.scan_policy.max_crawl_depth} · max{" "}
              {Math.round(project.scan_policy.max_duration_seconds / 60)} min
            </Text>
            <Text size="sm">
              Evidence retention:{" "}
              {project.scan_policy.evidence_retention_days ? `${project.scan_policy.evidence_retention_days} days` : "until manually deleted"}
            </Text>
          </Card>
          <Card withBorder component="section" aria-labelledby="last-h">
            <Title order={2} size="h4" id="last-h" mb="sm">
              Last scan
            </Title>
            {last_scan ? (
              <Group>
                <ScanStateLabel state={last_scan.state} />
                <Text size="sm">{formatDateTime(last_scan.at)}</Text>
              </Group>
            ) : (
              <Text size="sm" c="dimmed">
                No scans recorded for this project.
              </Text>
            )}
            <Anchor component={Link} to={`/findings?project_id=${project.project_id}`} size="sm" display="block" mt="sm">
              View this project's findings
            </Anchor>
          </Card>
        </SimpleGrid>

        <RecentChanges projectId={project.project_id} />
      </Stack>

      {deleting && <DeleteProjectModal projectId={project.project_id} onClose={() => setDeleting(false)} />}
    </>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <Table.Tr>
      <Table.Th w={140}>{label}</Table.Th>
      <Table.Td style={{ wordBreak: "break-word" }}>{value}</Table.Td>
    </Table.Tr>
  );
}

export function ScopeSummary({ scope }: { scope: ScopeDefinition }) {
  const groups: [string, (string | number)[]][] = [
    ["Schemes", scope.schemes],
    ["Hosts", scope.hosts],
    ["Wildcard domains", scope.wildcard_domains],
    ["IP ranges", scope.ip_ranges],
    ["Ports", scope.ports],
    ["Path prefixes", scope.path_prefixes],
    ["API server URLs", scope.api_server_urls],
    ["Excluded hosts", [...scope.exclusions.hosts, ...scope.exclusions.wildcard_domains, ...scope.exclusions.ip_ranges]],
    ["Excluded ports", scope.exclusions.ports],
    ["Excluded paths", scope.exclusions.path_prefixes],
  ];
  return (
    <Stack gap={6}>
      {groups
        .filter(([, values]) => values.length > 0)
        .map(([label, values]) => (
          <div key={label}>
            <Text size="xs" c="dimmed">
              {label}
            </Text>
            <Group gap={4}>
              {values.map((v) => (
                <Code key={String(v)}>{String(v)}</Code>
              ))}
            </Group>
          </div>
        ))}
    </Stack>
  );
}

function RecentChanges({ projectId }: { projectId: string }) {
  const audit = useAudit({ project_id: projectId, limit: 10 });
  return (
    <Card withBorder component="section" aria-labelledby="changes-h">
      <Title order={2} size="h4" id="changes-h" mb="sm">
        Recent changes
      </Title>
      <QueryState query={audit}>
        {(page) =>
          page.items.length === 0 ? (
            <Text size="sm" c="dimmed">No changes recorded.</Text>
          ) : (
            <List size="sm" spacing={4}>
              {page.items.map((e) => (
                <List.Item key={e.event_id}>
                  {humanize(e.action)} — {formatDateTime(e.ts)}
                </List.Item>
              ))}
            </List>
          )
        }
      </QueryState>
    </Card>
  );
}

export function DeleteProjectModal({ projectId, onClose }: { projectId: string; onClose: () => void }) {
  const impact = useDeletionImpact(projectId, true);
  const remove = useDeleteProject(projectId);
  const navigate = useNavigate();
  const [typed, setTyped] = useState("");
  const matches = impact.data !== undefined && typed === impact.data.confirm_with;

  const confirm = () =>
    remove.mutate(typed, {
      onSuccess: (result) => {
        notifications.show({ color: "green", message: `Deleted project “${result.name}”` });
        onClose();
        navigate("/projects");
      },
    });

  return (
    <Modal opened onClose={onClose} title="Delete project permanently" centered>
      {impact.isPending ? (
        <Loading label="Counting what will be removed…" />
      ) : impact.isError || !impact.data ? (
        <ErrorAlert error={impact.error} />
      ) : (
        <Stack>
          <Text size="sm">This permanently removes the project folder and everything stored under it:</Text>
          <List size="sm">
            {Object.entries(impact.data.counts).map(([kind, n]) => (
              <List.Item key={kind}>
                {n} {humanize(kind)} record(s)
              </List.Item>
            ))}
          </List>
          <Text size="sm">The audit log keeps a record of the deletion. This cannot be undone.</Text>
          <TextInput
            label={`Type the project name to confirm: ${impact.data.confirm_with}`}
            value={typed}
            onChange={(e) => setTyped(e.currentTarget.value)}
            data-autofocus
          />
          {remove.isError && <ErrorAlert error={remove.error} title="Deletion failed" />}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button color="red" disabled={!matches} loading={remove.isPending} onClick={confirm}>
              Delete project
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
