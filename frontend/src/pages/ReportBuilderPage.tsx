import { Anchor, Badge, Button, Card, Checkbox, Group, List, MultiSelect, Select, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  backupExportUrl,
  exportUrl,
  reportDownloadUrl,
  useGenerateReport,
  usePreviewReport,
  useProject,
  useReports,
} from "../api/hooks";
import type { AnalystStatus, ReportFormat, ReportPreviewResponse, Severity } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { EmptyState, QueryState } from "../components/QueryState";
import { formatDateTime, humanize } from "../lib/format";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
const STATUSES: AnalystStatus[] = ["new", "confirmed", "false_positive", "accepted_risk", "fixed", "retest_needed", "needs_review"];
const MODULES = ["web_app", "attack_surface", "api_security", "import", "unknown"];
const FORMATS: ReportFormat[] = ["html", "pdf", "json", "csv"];

export function ReportBuilderPage() {
  const { projectId = "" } = useParams();
  const project = useProject(projectId);
  const reports = useReports(projectId);
  const previewMutation = usePreviewReport(projectId);
  const generateMutation = useGenerateReport(projectId);

  const [title, setTitle] = useState("VAPT Assessment Report");
  const [classification, setClassification] = useState("CONFIDENTIAL");
  const [severityThreshold, setSeverityThreshold] = useState<Severity>("informational");
  const [statuses, setStatuses] = useState<string[]>([]);
  const [modules, setModules] = useState<string[]>([]);
  const [includeAssets, setIncludeAssets] = useState(true);
  const [includeEvidence, setIncludeEvidence] = useState(true);
  const [formats, setFormats] = useState<string[]>(["html", "pdf"]);
  const [preview, setPreview] = useState<ReportPreviewResponse | null>(null);

  const filterBody = () => ({
    title, classification_label: classification,
    severity_threshold: severityThreshold,
    analyst_statuses: statuses.length ? (statuses as AnalystStatus[]) : null,
    modules: modules.length ? modules : null,
    include_asset_inventory: includeAssets, include_evidence: includeEvidence,
  });

  const doPreview = () => {
    previewMutation.mutate(filterBody(), {
      onSuccess: (data) => setPreview(data),
      onError: (e) => notifications.show({ color: "red", title: "Preview failed", message: e instanceof ApiError ? e.describe() : "Preview failed" }),
    });
  };

  const doGenerate = () => {
    generateMutation.mutate(
      { ...filterBody(), formats: formats as ReportFormat[] },
      {
        onSuccess: () => notifications.show({ color: "green", message: "Report generated" }),
        onError: (e) => notifications.show({ color: "red", title: "Generation failed", message: e instanceof ApiError ? e.describe() : "Generation failed" }),
      },
    );
  };

  return (
    <>
      <PageHeader
        title="Report builder"
        description={project.data?.project.name}
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Projects", to: "/projects" },
          { label: project.data?.project.name ?? "…", to: `/projects/${projectId}` }, { label: "Reports" }]}
      />
      <Stack gap="md">
        <Card withBorder component="section" aria-labelledby="builder-h">
          <Title order={2} size="h4" id="builder-h" mb="sm">Build a report</Title>
          <Stack gap="sm">
            <Group grow>
              <TextInput label="Title" value={title} onChange={(e) => setTitle(e.currentTarget.value)} />
              <TextInput label="Classification label" value={classification} onChange={(e) => setClassification(e.currentTarget.value)} />
            </Group>
            <Group grow>
              <Select label="Minimum severity" data={SEVERITIES.map((s) => ({ value: s, label: humanize(s) }))}
                     value={severityThreshold} onChange={(v) => setSeverityThreshold((v as Severity) ?? "informational")} />
              <MultiSelect label="Analyst states (default: all but false positive)"
                          data={STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
                          value={statuses} onChange={setStatuses} clearable />
              <MultiSelect label="Modules (default: all)" data={MODULES.map((m) => ({ value: m, label: humanize(m) }))}
                          value={modules} onChange={setModules} clearable />
            </Group>
            <Group>
              <Checkbox label="Include asset inventory" checked={includeAssets} onChange={(e) => setIncludeAssets(e.currentTarget.checked)} />
              <Checkbox label="Include evidence excerpts" checked={includeEvidence} onChange={(e) => setIncludeEvidence(e.currentTarget.checked)} />
            </Group>
            <MultiSelect label="Formats to generate" data={FORMATS.map((f) => ({ value: f, label: f.toUpperCase() }))}
                        value={formats} onChange={setFormats} />
            <Group>
              <Button variant="default" onClick={doPreview} loading={previewMutation.isPending}>Preview</Button>
              <Button onClick={doGenerate} loading={generateMutation.isPending} disabled={formats.length === 0}>
                Generate report
              </Button>
            </Group>
          </Stack>
        </Card>

        {preview && (
          <Card withBorder component="section" aria-labelledby="preview-h">
            <Title order={3} size="h5" id="preview-h" mb="sm">
              Preview — {preview.finding_ids.length} finding(s), {preview.asset_ids.length} asset(s)
            </Title>
            <Group gap="xs" mb="sm">
              {Object.entries(preview.severity_counts).filter(([, n]) => n > 0).map(([s, n]) => (
                <Badge key={s} variant="outline">{humanize(s)}: {n}</Badge>
              ))}
            </Group>
            {preview.limitations.length > 0 && (
              <>
                <Text size="sm" fw={600}>Limitations that will be included:</Text>
                <List size="sm">{preview.limitations.slice(0, 10).map((l, i) => <List.Item key={i}>{l}</List.Item>)}</List>
              </>
            )}
          </Card>
        )}

        <Card withBorder component="section" aria-labelledby="exports-h">
          <Title order={3} size="h5" id="exports-h" mb="sm">Standalone exports</Title>
          <Group gap="sm">
            <Anchor href={exportUrl(projectId, "findings", "json")}>Findings JSON</Anchor>
            <Anchor href={exportUrl(projectId, "findings", "csv")}>Findings CSV</Anchor>
            <Anchor href={exportUrl(projectId, "assets", "json")}>Assets JSON</Anchor>
            <Anchor href={exportUrl(projectId, "assets", "csv")}>Assets CSV</Anchor>
            <Anchor href={backupExportUrl(projectId, true)}>Full project backup (.zip)</Anchor>
          </Group>
        </Card>

        <QueryState query={reports} loadingLabel="Loading reports…">
          {(list) => list.length === 0 ? (
            <Card withBorder><EmptyState title="No reports generated yet" /></Card>
          ) : (
            <Card withBorder p={0}>
              <Table striped aria-label="Generated reports">
                <Table.Thead><Table.Tr>
                  <Table.Th scope="col">Title</Table.Th><Table.Th scope="col">Findings</Table.Th>
                  <Table.Th scope="col">Generated</Table.Th><Table.Th scope="col">Downloads</Table.Th>
                </Table.Tr></Table.Thead>
                <Table.Tbody>
                  {list.map((r) => (
                    <Table.Tr key={r.report_id}>
                      <Table.Td>{r.title}<Text size="xs" c="dimmed">{r.classification_label}</Text></Table.Td>
                      <Table.Td>{r.finding_count}</Table.Td>
                      <Table.Td>{formatDateTime(r.created_at)}</Table.Td>
                      <Table.Td>
                        <Group gap="xs">
                          {r.formats.map((f) => (
                            <Anchor key={f} href={reportDownloadUrl(projectId, r.report_id, f)}>{f.toUpperCase()}</Anchor>
                          ))}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Card>
          )}
        </QueryState>
      </Stack>
    </>
  );
}
