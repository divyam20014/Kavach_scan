import { Alert, Anchor, Badge, Button, Card, Group, List, Modal, Select, SimpleGrid, Stack, Table, Text, Textarea, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  useAddFindingComment,
  useAudit,
  useFindingDetail,
  useMergeFinding,
  useUnmergeFinding,
  useUpdateFinding,
} from "../api/hooks";
import type { AnalystStatus, BusinessPriority, FindingDetailView } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { SeverityLabel } from "../components/StatusLabel";
import { formatDateTime, humanize } from "../lib/format";

const STATUSES: AnalystStatus[] = ["new", "confirmed", "false_positive", "accepted_risk", "fixed", "retest_needed", "needs_review"];
const PRIORITIES: BusinessPriority[] = ["p1", "p2", "p3", "p4"];

export function FindingDetailPage() {
  const { projectId = "", findingId = "" } = useParams();
  const detail = useFindingDetail(projectId, findingId);
  return (
    <>
      <PageHeader
        title="Finding"
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Findings", to: "/findings" }, { label: "Detail" }]}
      />
      <QueryState query={detail} loadingLabel="Loading finding…">
        {(d) => <FindingDetailBody projectId={projectId} findingId={findingId} detail={d} />}
      </QueryState>
    </>
  );
}

function RiskBadge({ tier, score }: { tier: string; score: number }) {
  return <Badge variant="outline" title="Internal prioritization score — not CVSS">{humanize(tier)} risk ({score}/100)</Badge>;
}

function FindingDetailBody({
  projectId, findingId, detail,
}: { projectId: string; findingId: string; detail: FindingDetailView }) {
  const f = detail.finding;
  const update = useUpdateFinding(projectId, findingId);
  const addComment = useAddFindingComment(projectId, findingId);
  const merge = useMergeFinding(projectId, findingId);
  const unmerge = useUnmergeFinding(projectId, findingId);
  const audit = useAudit({ target_id: findingId, limit: 50 });

  const [status, setStatus] = useState<AnalystStatus>(f.analyst_status);
  const [priority, setPriority] = useState<BusinessPriority | "">(f.business_priority ?? "");
  const [impact, setImpact] = useState(f.business_impact);
  const [remediation, setRemediation] = useState(f.remediation);
  const [comment, setComment] = useState("");
  const [mergeTarget, setMergeTarget] = useState("");
  const [mergeOpen, setMergeOpen] = useState(false);

  const saveTriage = () => {
    update.mutate(
      {
        expected_revision: f.revision, analyst_status: status,
        business_priority: priority || null, business_impact: impact, remediation,
      },
      {
        onSuccess: () => notifications.show({ color: "green", message: "Triage saved" }),
        onError: (e) => notifications.show({ color: "red", title: "Save failed", message: e instanceof ApiError ? e.describe() : "Save failed" }),
      },
    );
  };

  const postComment = () => {
    if (!comment.trim()) return;
    addComment.mutate(
      { text: comment, expected_revision: f.revision },
      {
        onSuccess: () => { setComment(""); notifications.show({ color: "green", message: "Comment added" }); },
        onError: (e) => notifications.show({ color: "red", title: "Comment failed", message: e instanceof ApiError ? e.describe() : "Comment failed" }),
      },
    );
  };

  const doMerge = () => {
    if (!mergeTarget.trim()) return;
    merge.mutate(
      { into_finding_id: mergeTarget.trim(), expected_revision: f.revision },
      {
        onSuccess: () => { setMergeOpen(false); notifications.show({ color: "green", message: "Marked as a duplicate" }); },
        onError: (e) => notifications.show({ color: "red", title: "Merge failed", message: e instanceof ApiError ? e.describe() : "Merge failed" }),
      },
    );
  };

  const doUnmerge = () => {
    unmerge.mutate(
      { expected_revision: f.revision },
      {
        onSuccess: () => notifications.show({ color: "green", message: "Unmerged" }),
        onError: (e) => notifications.show({ color: "red", title: "Unmerge failed", message: e instanceof ApiError ? e.describe() : "Unmerge failed" }),
      },
    );
  };

  return (
    <Stack gap="md">
      <Card withBorder>
        <Group justify="space-between" align="flex-start" mb="sm">
          <div>
            <Title order={2} size="h3">{f.title}</Title>
            <Group gap="xs" mt="xs">
              <SeverityLabel severity={f.severity} />
              <Badge variant="light">{humanize(f.confidence)}</Badge>
              <RiskBadge tier={detail.risk.tier as string} score={detail.risk.score as number} />
              <Badge variant="outline">{humanize(detail.module)}</Badge>
            </Group>
          </div>
        </Group>
        {f.merged_into && (
          <Alert color="gray" variant="light" title="This finding is merged" mb="sm">
            It is marked as a duplicate of{" "}
            <Anchor component={Link} to={`/projects/${projectId}/findings/${f.merged_into}`}>another finding</Anchor>.
            {" "}<Button size="compact-xs" variant="light" onClick={doUnmerge} loading={unmerge.isPending}>Unmerge</Button>
          </Alert>
        )}
        {detail.merged_duplicates.length > 0 && (
          <Alert color="blue" variant="light" title="Duplicates merged into this finding" mb="sm">
            <List size="sm">
              {detail.merged_duplicates.map((d) => (
                <List.Item key={d.finding_id}>
                  <Anchor component={Link} to={`/projects/${projectId}/findings/${d.finding_id}`}>{d.title}</Anchor>
                </List.Item>
              ))}
            </List>
          </Alert>
        )}
        {f.summary && <Text size="sm" mb="sm">{f.summary}</Text>}
        {f.url && <Text size="sm" c="dimmed" mb="sm" style={{ wordBreak: "break-all" }}>{f.url}{f.parameter ? ` · ${f.parameter}` : ""}</Text>}
        {f.technical_detail && (
          <Card withBorder bg="var(--mantine-color-gray-0)" mb="sm">
            <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{f.technical_detail}</Text>
          </Card>
        )}
        {!f.merged_into && (
          <Group gap="xs">
            <Button size="compact-sm" variant="default" onClick={() => setMergeOpen(true)}>Mark as duplicate…</Button>
          </Group>
        )}
      </Card>

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
        <Card withBorder component="section" aria-labelledby="triage-h">
          <Title order={3} size="h5" id="triage-h" mb="sm">Analyst triage</Title>
          <Stack gap="sm">
            <Select label="Status" data={STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
                   value={status} onChange={(v) => setStatus((v as AnalystStatus) ?? status)} />
            <Select label="Business priority" data={PRIORITIES.map((p) => ({ value: p, label: p.toUpperCase() }))}
                   value={priority || null} onChange={(v) => setPriority((v as BusinessPriority) ?? "")} clearable />
            <Textarea label="Business impact" value={impact} onChange={(e) => setImpact(e.currentTarget.value)} autosize minRows={2} />
            <Textarea label="Remediation" value={remediation} onChange={(e) => setRemediation(e.currentTarget.value)} autosize minRows={2} />
            <Button onClick={saveTriage} loading={update.isPending} w="fit-content">Save triage</Button>
            <Text size="xs" c="dimmed">
              Scanner-reported severity, confidence, CWE, and evidence are never changed here — only analyst-owned fields.
            </Text>
          </Stack>
        </Card>

        <Card withBorder component="section" aria-labelledby="risk-h">
          <Title order={3} size="h5" id="risk-h" mb="sm">Risk score breakdown</Title>
          <Text size="xs" c="dimmed" mb="sm">Internal prioritization only — not CVSS, never fabricated.</Text>
          <Table>
            <Table.Tbody>
              <Table.Tr><Table.Td>Severity × confidence</Table.Td><Table.Td>{detail.risk.severity_after_confidence as number}</Table.Td></Table.Tr>
              <Table.Tr><Table.Td>Asset criticality bonus</Table.Td><Table.Td>{detail.risk.asset_criticality_bonus as number}</Table.Td></Table.Tr>
              <Table.Tr><Table.Td>Exposure bonus</Table.Td><Table.Td>{detail.risk.exposure_bonus as number}</Table.Td></Table.Tr>
              <Table.Tr><Table.Td>Verification bonus</Table.Td><Table.Td>{detail.risk.verification_bonus as number}</Table.Td></Table.Tr>
              <Table.Tr><Table.Td><b>Score</b></Table.Td><Table.Td><b>{detail.risk.score as number} / 100 ({humanize(detail.risk.tier as string)})</b></Table.Td></Table.Tr>
            </Table.Tbody>
          </Table>
          {detail.risk.capped_for_needs_review as boolean && (
            <Text size="xs" c="dimmed" mt="xs">Capped at "high": confidence is needs_review, so this can never show as critical.</Text>
          )}
        </Card>
      </SimpleGrid>

      <Card withBorder component="section" aria-labelledby="provenance-h">
        <Title order={3} size="h5" id="provenance-h" mb="sm">Source provenance</Title>
        <Table.ScrollContainer minWidth={700}>
          <Table striped aria-label="Finding sources">
            <Table.Thead><Table.Tr>
              <Table.Th scope="col">Tool</Table.Th><Table.Th scope="col">Rule / ID</Table.Th>
              <Table.Th scope="col">Original rating</Table.Th><Table.Th scope="col">Observed</Table.Th>
            </Table.Tr></Table.Thead>
            <Table.Tbody>
              {f.sources.map((s, i) => (
                <Table.Tr key={i}>
                  <Table.Td>{s.tool}{s.tool_version ? ` ${s.tool_version}` : ""}</Table.Td>
                  <Table.Td>{s.rule_id || s.source_finding_id || "—"}</Table.Td>
                  <Table.Td>{s.original_severity || "—"}{s.original_confidence ? ` / ${s.original_confidence}` : ""}</Table.Td>
                  <Table.Td>{formatDateTime(s.observed_at)}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {(f.mappings.length > 0 || f.cwe_ids.length > 0) && (
          <Group gap="xs" mt="sm">
            {f.mappings.map((m) => (
              <Badge key={`${m.catalog}-${m.entry_id}`} variant="light" title={m.rationale}>
                {m.entry_id} ({m.catalog_version}){m.title ? `: ${m.title}` : ""}
              </Badge>
            ))}
            {f.cwe_ids.filter((id) => !f.mappings.some((m) => m.catalog === "cwe" && m.entry_id === `CWE-${id}`)).map((id) => (
              <Badge key={id} variant="outline">CWE-{id}</Badge>
            ))}
          </Group>
        )}
        {f.cvss && (
          <Text size="sm" mt="sm">
            CVSS {f.cvss.version}: <code>{f.cvss.vector}</code> — base score {f.cvss.base_score} (verified by {f.cvss.calculator || "cvss"})
          </Text>
        )}
        {f.dedup_history.length > 0 && (
          <>
            <Title order={4} size="h6" mt="md" mb="xs">Dedup history</Title>
            <List size="sm">
              {f.dedup_history.map((e, i) => (
                <List.Item key={i}>{humanize(e.action)} — {formatDateTime(e.at)}{e.note ? ` (${e.note})` : ""}</List.Item>
              ))}
            </List>
          </>
        )}
      </Card>

      <Card withBorder component="section" aria-labelledby="comments-h">
        <Title order={3} size="h5" id="comments-h" mb="sm">Comments</Title>
        {f.comments.length === 0 ? (
          <Text size="sm" c="dimmed">No comments yet.</Text>
        ) : (
          <Stack gap="xs" mb="sm">
            {f.comments.map((c) => (
              <Card key={c.comment_id} withBorder padding="xs">
                <Text size="xs" c="dimmed">{c.author} · {formatDateTime(c.created_at)}</Text>
                <Text size="sm">{c.text}</Text>
              </Card>
            ))}
          </Stack>
        )}
        <Group align="flex-end" gap="xs">
          <Textarea placeholder="Add a note…" value={comment} onChange={(e) => setComment(e.currentTarget.value)} style={{ flex: 1 }} autosize minRows={1} />
          <Button onClick={postComment} loading={addComment.isPending}>Add</Button>
        </Group>
      </Card>

      <Card withBorder component="section" aria-labelledby="audit-h">
        <Title order={3} size="h5" id="audit-h" mb="sm">Audit history</Title>
        <QueryState query={audit} loadingLabel="Loading audit history…">
          {(page) => page.items.length === 0 ? (
            <EmptyState title="No audit events yet" />
          ) : (
            <List size="sm">
              {page.items.map((e) => (
                <List.Item key={e.event_id}>{formatDateTime(e.ts)} — {humanize(e.action)}</List.Item>
              ))}
            </List>
          )}
        </QueryState>
      </Card>

      <Modal opened={mergeOpen} onClose={() => setMergeOpen(false)} title="Mark as duplicate">
        <Stack gap="sm">
          <Text size="sm">Enter the finding ID this is a duplicate of. Both records are kept; this one is hidden from the default list and cross-referenced for rollback.</Text>
          <TextInput label="Canonical finding ID" placeholder="fnd_…" value={mergeTarget} onChange={(e) => setMergeTarget(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setMergeOpen(false)}>Cancel</Button>
            <Button onClick={doMerge} loading={merge.isPending}>Merge</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
