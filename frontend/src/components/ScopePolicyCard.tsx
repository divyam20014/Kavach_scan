import { Alert, Badge, Button, Card, Checkbox, Code, Group, Stack, Table, Text, TextInput, Textarea, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { ApiError } from "../api/client";
import { useRemoveOverride, useScopeCheck, useScopePolicy, useSetOverride } from "../api/hooks";
import type { BlockedRange, Decision, Project } from "../api/types";
import { formatDateTime, humanize, localInputToIso, splitLines } from "../lib/format";
import { ErrorAlert, QueryState } from "./QueryState";

export function BlockedRangesTable({ ranges }: { ranges: BlockedRange[] }) {
  return (
    <details>
      <summary style={{ cursor: "pointer" }}>
        <Text span size="sm" fw={600}>
          Blocked by default: {ranges.length} address ranges
        </Text>
      </summary>
      <Table.ScrollContainer minWidth={520} mt="xs">
        <Table aria-label="Default-blocked address ranges" striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th scope="col">Range</Table.Th>
              <Table.Th scope="col">Why</Table.Th>
              <Table.Th scope="col">Override possible</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {ranges.map((r) => (
              <Table.Tr key={r.network}>
                <Table.Td><Code>{r.network}</Code></Table.Td>
                <Table.Td>{r.label}</Table.Td>
                <Table.Td>{r.overridable ? "Yes (audited, time-limited)" : "✕ Never"}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </details>
  );
}

function DecisionLine({ d }: { d: Decision }) {
  return (
    <Text size="sm">
      {d.allowed ? "✓" : "✕"} <strong>{humanize(d.check)}</strong>: {d.message}
      {d.rule && (
        <Text span size="xs" c="dimmed">
          {" "}
          (rule: {d.rule})
        </Text>
      )}
    </Text>
  );
}

export function ScopePolicyCard({ project }: { project: Project }) {
  const policy = useScopePolicy(project.project_id);
  return (
    <Card withBorder component="section" aria-labelledby="policy-h">
      <Title order={2} size="h4" id="policy-h" mb="sm">
        Scope policy &amp; safety gate
      </Title>
      <QueryState query={policy} loadingLabel="Loading scope policy…">
        {(view) => (
          <Stack gap="sm">
            <Group gap="sm">
              <Badge color={view.can_start_active_work ? "green" : "red"} variant="light"
                leftSection={<span aria-hidden="true">{view.can_start_active_work ? "✓" : "✕"}</span>}>
                {view.can_start_active_work ? "Active work permitted" : "Active work blocked"}
              </Badge>
              <Text size="sm">{view.authorization.message}</Text>
            </Group>
            {view.warnings.map((w) => (
              <Alert key={w} color="yellow" role="note" variant="light">
                {w}
              </Alert>
            ))}
            <OverrideSection project={project} view={view.internal_override} />
            <UrlChecker projectId={project.project_id} />
            <BlockedRangesTable ranges={view.blocked_ranges} />
            <Text size="xs" c="dimmed">
              Scope hash <Code>{view.scope_hash.slice(0, 16)}…</Code>. Every request, redirect and resolved address is checked against this policy before any traffic is sent.
            </Text>
          </Stack>
        )}
      </QueryState>
    </Card>
  );
}

function UrlChecker({ projectId }: { projectId: string }) {
  const check = useScopeCheck(projectId);
  const [url, setUrl] = useState("");
  const [ips, setIps] = useState("");
  return (
    <Stack gap="xs">
      <Text size="sm" fw={600}>
        Check a URL against this scope (dry run: no DNS lookup, no request)
      </Text>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (url.trim()) check.mutate({ url: url.trim(), resolved_ips: splitLines(ips) });
        }}
      >
        <Group align="flex-end" wrap="wrap">
          <TextInput label="URL" placeholder="https://app.example.com/login" value={url} onChange={(e) => setUrl(e.currentTarget.value)} w={340} />
          <TextInput label="Simulated resolved IPs (optional)" placeholder="93.184.216.34" value={ips} onChange={(e) => setIps(e.currentTarget.value)} w={240} />
          <Button type="submit" variant="light" loading={check.isPending}>
            Check
          </Button>
        </Group>
      </form>
      {check.isError && <ErrorAlert error={check.error} title="Check failed" />}
      {check.data && (
        <Alert color={check.data.allowed ? "green" : "red"} variant="light" role="status" title={check.data.allowed ? "✓ Would be allowed" : "✕ Would be blocked"}>
          <Stack gap={2}>
            <DecisionLine d={check.data.authorization} />
            <DecisionLine d={check.data.target} />
            {check.data.resolved_ips.map((d) => (
              <DecisionLine d={d} key={d.decision_id} />
            ))}
            {check.data.dns_note && (
              <Text size="xs" c="dimmed">
                {check.data.dns_note}
              </Text>
            )}
          </Stack>
        </Alert>
      )}
    </Stack>
  );
}

function OverrideSection({ project, view }: { project: Project; view: { override: { ip_ranges: string[]; reason: string; expires_at: string; audit_event_id: string }; active: boolean } | null }) {
  const [open, setOpen] = useState(false);
  const [ranges, setRanges] = useState("");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [attest, setAttest] = useState(false);
  const set = useSetOverride(project.project_id);
  const remove = useRemoveOverride(project.project_id);
  const fail = (e: unknown) =>
    notifications.show({ color: "red", title: "Override change failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" });

  if (view) {
    return (
      <Alert color={view.active ? "orange" : "gray"} variant="light" role="note" title={view.active ? "Internal-target override active" : "Internal-target override expired"}>
        <Stack gap={4}>
          <Text size="sm">
            Ranges: {view.override.ip_ranges.map((r) => <Code key={r} mr={4}>{r}</Code>)}
          </Text>
          <Text size="sm">Reason: {view.override.reason}</Text>
          <Text size="sm">Expires: {formatDateTime(view.override.expires_at)}</Text>
          <Button size="xs" color="red" variant="light" w="fit-content" loading={remove.isPending}
            onClick={() => remove.mutate(project.revision, { onError: fail, onSuccess: () => notifications.show({ color: "green", message: "Override removed" }) })}>
            Remove override
          </Button>
        </Stack>
      </Alert>
    );
  }
  if (!open) {
    return (
      <Group gap="xs">
        <Text size="sm" c="dimmed">No internal-target override: private, loopback and link-local addresses are blocked.</Text>
        <Button size="xs" variant="subtle" onClick={() => setOpen(true)}>
          Add override…
        </Button>
      </Group>
    );
  }
  return (
    <Card withBorder padding="sm">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          set.mutate(
            { expected_revision: project.revision, ip_ranges: splitLines(ranges), reason, expires_at: expires ? localInputToIso(expires) : "", attestation: attest },
            { onSuccess: () => { setOpen(false); notifications.show({ color: "green", message: "Override recorded in the audit log" }); } },
          );
        }}
      >
        <Stack gap="xs">
          <Text size="sm" fw={600}>Internal-target override</Text>
          <Text size="xs" c="dimmed">Narrow (IPv4 /16 or smaller), time-limited (≤ 90 days) and audited. Cloud metadata addresses can never be overridden.</Text>
          <Textarea label="Blocked ranges to allow" placeholder="10.20.0.0/24" value={ranges} onChange={(e) => setRanges(e.currentTarget.value)} autosize minRows={1} required />
          <TextInput label="Reason" value={reason} onChange={(e) => setReason(e.currentTarget.value)} required />
          <TextInput type="datetime-local" label="Expires (local time)" value={expires} onChange={(e) => setExpires(e.currentTarget.value)} required />
          <Checkbox label="Operator attestation: these internal addresses are covered by my written authorization." checked={attest} onChange={(e) => setAttest(e.currentTarget.checked)} />
          {set.isError && <ErrorAlert error={set.error} title="Override rejected" />}
          <Group>
            <Button type="submit" size="xs" loading={set.isPending}>Save override</Button>
            <Button size="xs" variant="default" onClick={() => setOpen(false)}>Cancel</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}
