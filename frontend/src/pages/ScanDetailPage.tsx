import { Alert, Anchor, Badge, Button, Card, Code, Group, Modal, Progress, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useCancelScan, useRetryScan, useScanConsole, useScanDetail, useScanEvents } from "../api/hooks";
import type { ScanDetail } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ErrorAlert, QueryState } from "../components/QueryState";
import { ScanStateLabel } from "../components/StatusLabel";
import { formatDateTime, humanize } from "../lib/format";

const RETRYABLE = new Set(["failed", "interrupted", "cancelled", "expired_authorization", "blocked_scope", "completed_with_warnings"]);

export function ScanDetailPage() {
  const { projectId = "", scanId = "" } = useParams();
  const detail = useScanDetail(projectId, scanId);
  return (
    <QueryState query={detail} loadingLabel="Loading job…">
      {(data) => <ScanDetailView detail={data} />}
    </QueryState>
  );
}

function ScanDetailView({ detail }: { detail: ScanDetail }) {
  const { scan } = detail;
  const live = !detail.terminal;
  const events = useScanEvents(scan.project_id, scan.scan_id, live);
  const consoleLog = useScanConsole(scan.project_id, scan.scan_id, live);
  const cancel = useCancelScan(scan.project_id, scan.scan_id);
  const retry = useRetryScan(scan.project_id, scan.scan_id);
  const navigate = useNavigate();
  const [confirmCancel, setConfirmCancel] = useState(false);
  const counters = Object.entries(scan.progress.counters);
  const { refetch: refetchEvents } = events;
  const { refetch: refetchConsole } = consoleLog;
  // Polling stops once the job is terminal; fetch once more so the final events/log lines
  // written at completion are shown (they land after the last live poll).
  useEffect(() => {
    if (detail.terminal) {
      void refetchEvents();
      void refetchConsole();
    }
  }, [detail.terminal, refetchEvents, refetchConsole]);

  const doRetry = () =>
    retry.mutate(undefined, {
      onSuccess: (s) => {
        notifications.show({ color: "green", message: "New job queued" });
        navigate(`/projects/${s.project_id}/scans/${s.scan_id}`);
      },
      onError: (e) => notifications.show({ color: "red", title: "Retry failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
    });

  return (
    <>
      <PageHeader
        title={`Job ${scan.scan_id.slice(4, 12)}`}
        description={`${humanize(scan.module)} · queued ${formatDateTime(scan.queued_at)}`}
        crumbs={[
          { label: "Dashboard", to: "/" },
          { label: "Scans", to: "/scans" },
          { label: scan.scan_id.slice(0, 12) + "…" },
        ]}
        actions={
          <>
            <Button component={Link} to={`/projects/${scan.project_id}`} variant="default">
              Project
            </Button>
            {live && (
              <Button color="red" onClick={() => setConfirmCancel(true)} disabled={scan.cancel_requested}>
                {scan.cancel_requested ? "Cancelling…" : "Cancel job"}
              </Button>
            )}
            {!live && RETRYABLE.has(scan.state) && (
              <Button variant="light" onClick={doRetry} loading={retry.isPending}>
                Retry as new job
              </Button>
            )}
          </>
        }
      />
      <Stack gap="md">
        <Card withBorder>
          <Group gap="md" wrap="wrap">
            <ScanStateLabel state={scan.state} />
            {live && <Badge variant="dot" color="blue">Live: refreshing every 1.5 s</Badge>}
            <Text size="sm">Stage: <strong>{scan.progress.stage || "—"}</strong></Text>
            <Text size="sm">Elapsed: {detail.elapsed_seconds === null ? "—" : `${detail.elapsed_seconds}s`}</Text>
            {scan.retry_of && (
              <Text size="sm">
                Retry of{" "}
                <Anchor component={Link} to={`/projects/${scan.project_id}/scans/${scan.retry_of}`}>
                  {scan.retry_of.slice(0, 12)}…
                </Anchor>
              </Text>
            )}
          </Group>
          {scan.progress.percent !== null && (
            <Progress value={scan.progress.percent} mt="sm" aria-label={`Progress ${scan.progress.percent}%`} />
          )}
          {scan.final_reason && (
            <Text size="sm" mt="sm">
              Result: {scan.final_reason}
            </Text>
          )}
        </Card>

        {scan.errors.length > 0 && (
          <Alert color="red" title={`${scan.errors.length} error(s)`} role="alert">
            {scan.errors.slice(-5).map((e) => <Text size="sm" key={e}>✕ {e}</Text>)}
          </Alert>
        )}
        {scan.warnings.length > 0 && (
          <Alert color="yellow" title={`${scan.warnings.length} warning(s)`} role="status">
            {scan.warnings.slice(-5).map((w) => <Text size="sm" key={w}>! {w}</Text>)}
          </Alert>
        )}

        <SimpleGrid cols={{ base: 1, md: 2 }}>
          <Card withBorder component="section" aria-labelledby="targets-h">
            <Title order={2} size="h4" id="targets-h" mb="sm">Targets (scope-checked)</Title>
            <Stack gap={4}>
              {scan.authorized_targets.map((t) => <Code key={t}>{t}</Code>)}
            </Stack>
            <Text size="xs" c="dimmed" mt="sm">Scope hash {scan.scope_hash?.slice(0, 16)}… · correlation {scan.correlation_id}</Text>
          </Card>
          <Card withBorder component="section" aria-labelledby="counters-h">
            <Title order={2} size="h4" id="counters-h" mb="sm">Counters</Title>
            {counters.length === 0 ? (
              <Text size="sm" c="dimmed">No counters yet.</Text>
            ) : (
              <Table>
                <Table.Tbody>
                  {counters.map(([k, v]) => (
                    <Table.Tr key={k}>
                      <Table.Th scope="row">{humanize(k)}</Table.Th>
                      <Table.Td ta="right">{v}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
            {scan.output_refs.length > 0 && (
              <Text size="sm" mt="sm">Outputs: {scan.output_refs.map((o) => <Code key={o} mr={4}>{o}</Code>)}</Text>
            )}
          </Card>
        </SimpleGrid>

        <Card withBorder component="section" aria-labelledby="events-h">
          <Title order={2} size="h4" id="events-h" mb="sm">Events (newest first)</Title>
          <QueryState query={events}>
            {(page) =>
              page.items.length === 0 ? (
                <Text size="sm" c="dimmed">No events yet.</Text>
              ) : (
                <Table.ScrollContainer minWidth={640}>
                  <Table striped aria-label="Job events">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th scope="col">Time</Table.Th>
                        <Table.Th scope="col">Level</Table.Th>
                        <Table.Th scope="col">Type</Table.Th>
                        <Table.Th scope="col">Message</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {page.items.map((e) => (
                        <Table.Tr key={e.event_id}>
                          <Table.Td>{formatDateTime(e.ts)}</Table.Td>
                          <Table.Td>{e.level === "error" ? "✕ error" : e.level === "warning" ? "! warning" : e.level}</Table.Td>
                          <Table.Td>{humanize(e.type)}</Table.Td>
                          <Table.Td style={{ wordBreak: "break-word" }}>{e.message}</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              )
            }
          </QueryState>
        </Card>

        <Card withBorder component="section" aria-labelledby="console-h">
          <Title order={2} size="h4" id="console-h" mb="sm">Console log</Title>
          <QueryState query={consoleLog}>
            {(c) => (
              <Code block style={{ maxHeight: 320, overflow: "auto", whiteSpace: "pre-wrap" }} aria-label="Console log output">
                {c.lines.length ? c.lines.join("\n") : "(empty)"}
              </Code>
            )}
          </QueryState>
        </Card>
      </Stack>

      <Modal opened={confirmCancel} onClose={() => setConfirmCancel(false)} title="Cancel this job?" centered>
        <Stack>
          <Text size="sm">The job stops scheduling new work, child processes are terminated and partial results are kept.</Text>
          {cancel.isError && <ErrorAlert error={cancel.error} title="Cancel failed" />}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setConfirmCancel(false)}>Keep running</Button>
            <Button color="red" loading={cancel.isPending}
              onClick={() => cancel.mutate(undefined, { onSuccess: () => { setConfirmCancel(false); notifications.show({ color: "orange", message: "Cancellation requested" }); } })}>
              Cancel job
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
