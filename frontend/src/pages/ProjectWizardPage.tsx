import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  NumberInput,
  Stack,
  Stepper,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useCreateProject, useProject, useScopePreview, useUpdateProject } from "../api/hooks";
import {
  SCAN_MODULES,
  type AuthorizationInput,
  type Project,
  type ProjectCreate,
  type ScanModule,
  type ScopeDefinition,
  type ScopePreviewResponse,
} from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ErrorAlert, QueryState } from "../components/QueryState";
import { isoToLocalInput, localInputToIso, splitLines } from "../lib/format";
import { BlockedRangesTable } from "../components/ScopePolicyCard";
import { ScopeSummary } from "./ProjectDetailPage";

export interface WizardValues {
  name: string;
  client_name: string;
  description: string;
  labels: string;
  notes: string;
  includeAuthorization: boolean;
  organization: string;
  target_owner: string;
  authorized_by: string;
  reference: string;
  window_start: string;
  window_end: string;
  auth_notes: string;
  attestation: boolean;
  targets: string;
  schemes: ("http" | "https")[];
  ports: string;
  path_prefixes: string;
  exclude_targets: string;
  exclude_ports: string;
  exclude_paths: string;
  api_server_urls: string;
  repository_path: string;
  allowed_modules: ScanModule[];
  max_concurrency: number;
  requests_per_second: number;
  connect_timeout_seconds: number;
  read_timeout_seconds: number;
  max_crawl_depth: number;
  max_pages: number;
  max_duration_minutes: number;
  evidence_retention_days: number | "";
}

const EMPTY: WizardValues = {
  name: "",
  client_name: "",
  description: "",
  labels: "",
  notes: "",
  includeAuthorization: true,
  organization: "",
  target_owner: "",
  authorized_by: "",
  reference: "",
  window_start: "",
  window_end: "",
  auth_notes: "",
  attestation: false,
  targets: "",
  schemes: ["https"],
  ports: "",
  path_prefixes: "",
  exclude_targets: "",
  exclude_ports: "",
  exclude_paths: "",
  api_server_urls: "",
  repository_path: "",
  allowed_modules: [],
  max_concurrency: 2,
  requests_per_second: 2,
  connect_timeout_seconds: 5,
  read_timeout_seconds: 15,
  max_crawl_depth: 3,
  max_pages: 200,
  max_duration_minutes: 30,
  evidence_retention_days: "",
};

function fromProject(p: Project): WizardValues {
  const s = p.scope;
  const a = p.authorization;
  return {
    ...EMPTY,
    name: p.name,
    client_name: p.client_name,
    description: p.description,
    labels: p.labels.join(", "),
    notes: p.notes,
    includeAuthorization: a !== null,
    organization: a?.organization ?? "",
    target_owner: a?.target_owner ?? "",
    authorized_by: a?.authorized_by ?? "",
    reference: a?.reference ?? "",
    window_start: isoToLocalInput(a?.window_start),
    window_end: isoToLocalInput(a?.window_end),
    auth_notes: a?.notes ?? "",
    attestation: false, // re-attestation is required whenever authorization is changed
    targets: [...s.hosts, ...s.wildcard_domains, ...s.ip_ranges].join("\n"),
    schemes: s.schemes,
    ports: s.ports.join(", "),
    path_prefixes: s.path_prefixes.join("\n"),
    exclude_targets: [...s.exclusions.hosts, ...s.exclusions.wildcard_domains, ...s.exclusions.ip_ranges].join("\n"),
    exclude_ports: s.exclusions.ports.join(", "),
    exclude_paths: s.exclusions.path_prefixes.join("\n"),
    api_server_urls: s.api_server_urls.join("\n"),
    repository_path: p.repository_path,
    allowed_modules: p.scan_policy.allowed_modules,
    max_concurrency: p.scan_policy.max_concurrency,
    requests_per_second: p.scan_policy.requests_per_second,
    connect_timeout_seconds: p.scan_policy.connect_timeout_seconds,
    read_timeout_seconds: p.scan_policy.read_timeout_seconds,
    max_crawl_depth: p.scan_policy.max_crawl_depth,
    max_pages: p.scan_policy.max_pages,
    max_duration_minutes: Math.round(p.scan_policy.max_duration_seconds / 60),
    evidence_retention_days: p.scan_policy.evidence_retention_days ?? "",
  };
}

type Errors = Partial<Record<keyof WizardValues, string>>;

export function validateStep(step: number, v: WizardValues): Errors {
  const e: Errors = {};
  if (step === 0) {
    if (!v.name.trim()) e.name = "Project name is required";
    else if (v.name.length > 200) e.name = "Maximum 200 characters";
    if (!v.client_name.trim()) e.client_name = "Client name is required";
  }
  if (step === 1 && v.includeAuthorization) {
    if (!v.organization.trim()) e.organization = "Organization is required";
    if (!v.target_owner.trim()) e.target_owner = "Target owner is required";
    if (!v.authorized_by.trim()) e.authorized_by = "Authorized-by is required";
    if (!v.window_start) e.window_start = "Start of the authorization window is required";
    if (!v.window_end) e.window_end = "End of the authorization window is required";
    if (v.window_start && v.window_end && new Date(v.window_end) <= new Date(v.window_start))
      e.window_end = "End must be after start";
    if (!v.attestation) e.attestation = "You must attest that you hold this authorization";
  }
  if (step === 3 && v.allowed_modules.includes("repo_scan") && !v.repository_path.trim()) {
    e.repository_path = "A repository path is required when the repository scanner is allowed";
  }
  return e;
}

function buildAuthorization(v: WizardValues): AuthorizationInput {
  return {
    organization: v.organization.trim(),
    target_owner: v.target_owner.trim(),
    authorized_by: v.authorized_by.trim(),
    reference: v.reference.trim(),
    window_start: localInputToIso(v.window_start),
    window_end: localInputToIso(v.window_end),
    notes: v.auth_notes,
    attestation: v.attestation,
  };
}

function buildPolicy(v: WizardValues) {
  return {
    allowed_modules: v.allowed_modules,
    max_concurrency: v.max_concurrency,
    requests_per_second: v.requests_per_second,
    connect_timeout_seconds: v.connect_timeout_seconds,
    read_timeout_seconds: v.read_timeout_seconds,
    max_crawl_depth: v.max_crawl_depth,
    max_pages: v.max_pages,
    max_duration_seconds: v.max_duration_minutes * 60,
    evidence_retention_days: v.evidence_retention_days === "" ? null : v.evidence_retention_days,
  };
}

export function ProjectWizardPage() {
  const { projectId } = useParams();
  if (!projectId) return <ProjectWizard />;
  return <EditWizard projectId={projectId} />;
}

function EditWizard({ projectId }: { projectId: string }) {
  const query = useProject(projectId);
  return <QueryState query={query}>{(data) => <ProjectWizard existing={data.project} />}</QueryState>;
}

const STEPS = ["Project", "Authorization", "Scope", "Modules & limits", "Review"];

export function ProjectWizard({ existing }: { existing?: Project }) {
  const navigate = useNavigate();
  const initial = useMemo(() => (existing ? fromProject(existing) : EMPTY), [existing]);
  const [values, setValues] = useState<WizardValues>(initial);
  const [errors, setErrors] = useState<Errors>({});
  const [active, setActive] = useState(0);
  const [preview, setPreview] = useState<ScopePreviewResponse | null>(null);
  const [authorizationTouched, setAuthorizationTouched] = useState(!existing);
  const scopePreview = useScopePreview();
  const create = useCreateProject();
  const update = useUpdateProject(existing?.project_id ?? "");
  const saving = create.isPending || update.isPending;
  const saveError = create.error ?? update.error;
  const serverFieldErrors = saveError instanceof ApiError ? saveError.fieldErrors() : {};

  const set = <K extends keyof WizardValues>(key: K, value: WizardValues[K]) => {
    setValues((v) => ({ ...v, [key]: value }));
    setErrors((e) => ({ ...e, [key]: undefined }));
    if (["targets", "schemes", "ports", "path_prefixes", "exclude_targets", "exclude_ports", "exclude_paths", "api_server_urls"].includes(key)) {
      setPreview(null); // any scope edit invalidates the preview
    }
    if (["organization", "target_owner", "authorized_by", "reference", "window_start", "window_end", "auth_notes", "attestation", "includeAuthorization"].includes(key)) {
      setAuthorizationTouched(true);
    }
  };

  const runPreview = () =>
    scopePreview.mutate(
      {
        targets: splitLines(values.targets),
        schemes: values.schemes,
        ports: splitLines(values.ports),
        path_prefixes: splitLines(values.path_prefixes),
        exclude_targets: splitLines(values.exclude_targets),
        exclude_ports: splitLines(values.exclude_ports),
        exclude_paths: splitLines(values.exclude_paths),
        api_server_urls: splitLines(values.api_server_urls),
      },
      { onSuccess: setPreview },
    );

  const next = () => {
    const stepErrors = validateStep(active, existing && !authorizationTouched && active === 1 ? { ...values, includeAuthorization: false } : values);
    if (Object.keys(stepErrors).length) {
      setErrors(stepErrors);
      return;
    }
    if (active === 2 && !(preview?.valid && preview.scope)) {
      setErrors({ targets: "Preview the scope and fix any errors before continuing" });
      return;
    }
    setActive((a) => Math.min(a + 1, STEPS.length - 1));
  };

  const save = () => {
    const scope = preview?.scope as ScopeDefinition;
    const base = {
      name: values.name.trim(),
      client_name: values.client_name.trim(),
      description: values.description,
      labels: splitLines(values.labels),
      notes: values.notes,
      scope,
      scope_preview_hash: preview?.scope_hash ?? null, // proves this exact scope was previewed
      repository_path: values.repository_path.trim(),
      scan_policy: buildPolicy(values),
    };
    const onError = () => setActive((a) => a); // errors render inline below
    if (existing) {
      update.mutate(
        {
          ...base,
          expected_revision: existing.revision,
          ...(authorizationTouched && values.includeAuthorization ? { authorization: buildAuthorization(values) } : {}),
        },
        {
          onSuccess: (p) => {
            notifications.show({ color: "green", message: "Project updated" });
            navigate(`/projects/${p.project_id}`);
          },
          onError,
        },
      );
    } else {
      const body: ProjectCreate = { ...base, authorization: values.includeAuthorization ? buildAuthorization(values) : null };
      create.mutate(body, {
        onSuccess: (p) => {
          notifications.show({ color: "green", message: `Project “${p.name}” created` });
          navigate(`/projects/${p.project_id}`);
        },
        onError,
      });
    }
  };

  const fieldError = (k: keyof WizardValues, ...serverKeys: string[]) =>
    errors[k] ?? serverKeys.map((s) => serverFieldErrors[s]).find(Boolean);

  return (
    <>
      <PageHeader
        title={existing ? `Edit ${existing.name}` : "New project"}
        crumbs={[
          { label: "Dashboard", to: "/" },
          { label: "Projects", to: "/projects" },
          ...(existing ? [{ label: existing.name, to: `/projects/${existing.project_id}` }] : []),
          { label: existing ? "Edit" : "New" },
        ]}
      />
      <Card withBorder>
        <Stepper active={active} onStepClick={(s) => s < active && setActive(s)} size="sm" mb="lg" allowNextStepsSelect={false}>
          {STEPS.map((label) => (
            <Stepper.Step key={label} label={label} />
          ))}
        </Stepper>

        <form
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            if (active < STEPS.length - 1) next();
            else save();
          }}
        >
          {active === 0 && (
            <Stack>
              <Title order={2} size="h4">Project</Title>
              <TextInput label="Project name" required value={values.name} error={fieldError("name", "name")}
                onChange={(e) => set("name", e.currentTarget.value)} maxLength={200} />
              <TextInput label="Client name" required value={values.client_name} error={fieldError("client_name", "client_name")}
                onChange={(e) => set("client_name", e.currentTarget.value)} maxLength={200} />
              <Textarea label="Description" value={values.description} onChange={(e) => set("description", e.currentTarget.value)} autosize minRows={2} />
              <TextInput label="Labels" description="Comma separated" value={values.labels} error={serverFieldErrors.labels}
                onChange={(e) => set("labels", e.currentTarget.value)} />
            </Stack>
          )}

          {active === 1 && (
            <Stack>
              <Title order={2} size="h4">Authorization</Title>
              {existing && !authorizationTouched && (
                <Alert role="note" color="gray" variant="light">
                  The stored authorization is kept unless you change a field below. Changing it requires a new operator attestation.
                </Alert>
              )}
              <Checkbox
                label="Record an authorization now"
                description="Without one, the project is saved but flagged as unauthorized; scanning will require it."
                checked={values.includeAuthorization}
                onChange={(e) => set("includeAuthorization", e.currentTarget.checked)}
              />
              {values.includeAuthorization && (
                <>
                  <Group grow align="flex-start">
                    <TextInput label="Organization / client" required value={values.organization} error={fieldError("organization", "authorization.organization")}
                      onChange={(e) => set("organization", e.currentTarget.value)} />
                    <TextInput label="Target owner" required value={values.target_owner} error={fieldError("target_owner", "authorization.target_owner")}
                      onChange={(e) => set("target_owner", e.currentTarget.value)} />
                  </Group>
                  <Group grow align="flex-start">
                    <TextInput label="Authorized by" required value={values.authorized_by} error={fieldError("authorized_by", "authorization.authorized_by")}
                      onChange={(e) => set("authorized_by", e.currentTarget.value)} />
                    <TextInput label="Reference (contract / ticket)" value={values.reference}
                      onChange={(e) => set("reference", e.currentTarget.value)} />
                  </Group>
                  <Group grow align="flex-start">
                    <TextInput type="datetime-local" label="Window start (local time)" required value={values.window_start}
                      error={fieldError("window_start", "authorization.window_start", "authorization")} onChange={(e) => set("window_start", e.currentTarget.value)} />
                    <TextInput type="datetime-local" label="Window end (local time)" required value={values.window_end}
                      error={fieldError("window_end", "authorization.window_end")} onChange={(e) => set("window_end", e.currentTarget.value)} />
                  </Group>
                  <Textarea label="Notes" value={values.auth_notes} onChange={(e) => set("auth_notes", e.currentTarget.value)} autosize minRows={2} />
                  <Checkbox
                    label="Operator attestation: I confirm I hold written authorization to test these targets within this window."
                    description="This records your attestation with a timestamp in the audit log. It is not legal verification."
                    checked={values.attestation}
                    error={fieldError("attestation")}
                    onChange={(e) => set("attestation", e.currentTarget.checked)}
                  />
                </>
              )}
            </Stack>
          )}

          {active === 2 && (
            <Stack>
              <Title order={2} size="h4">Scope</Title>
              <Alert role="note" color="blue" variant="light">
                Preview normalizes and checks what you enter with the scope engine. Saving requires a fresh preview of exactly this scope.
              </Alert>
              <Textarea label="In-scope targets" required description="One per line: hostname, *.wildcard.domain, IP/CIDR, or http(s) URL"
                value={values.targets} error={errors.targets} onChange={(e) => set("targets", e.currentTarget.value)} autosize minRows={4} />
              <Group align="flex-start" grow>
                <Checkbox.Group label="Schemes" value={values.schemes} onChange={(v) => v.length && set("schemes", v as ("http" | "https")[])}>
                  <Group mt={4}>
                    <Checkbox value="https" label="https" />
                    <Checkbox value="http" label="http" />
                  </Group>
                </Checkbox.Group>
                <TextInput label="Ports" description="Comma separated; default 80, 443" value={values.ports} onChange={(e) => set("ports", e.currentTarget.value)} />
              </Group>
              <Textarea label="Path prefixes" description="Default: / (everything under the host)" value={values.path_prefixes}
                onChange={(e) => set("path_prefixes", e.currentTarget.value)} autosize minRows={1} />
              <Textarea label="Excluded targets" description="Hosts, wildcards or CIDRs that must never be touched" value={values.exclude_targets}
                onChange={(e) => set("exclude_targets", e.currentTarget.value)} autosize minRows={2} />
              <Group grow align="flex-start">
                <TextInput label="Excluded ports" value={values.exclude_ports} onChange={(e) => set("exclude_ports", e.currentTarget.value)} />
                <Textarea label="Excluded paths" value={values.exclude_paths} onChange={(e) => set("exclude_paths", e.currentTarget.value)} autosize minRows={1} />
              </Group>
              <Textarea label="API server URLs (optional)" value={values.api_server_urls} onChange={(e) => set("api_server_urls", e.currentTarget.value)} autosize minRows={1} />
              <Group>
                <Button variant="light" onClick={runPreview} loading={scopePreview.isPending}>
                  Preview scope
                </Button>
                {preview && (
                  <Badge color={preview.valid ? "green" : "red"} variant="light">
                    {preview.valid ? "✓ Scope is valid" : `✕ ${preview.error_count} problem(s)`}
                  </Badge>
                )}
              </Group>
              {scopePreview.isError && <ErrorAlert error={scopePreview.error} title="Preview failed" />}
              {preview && <PreviewTable preview={preview} />}
            </Stack>
          )}

          {active === 3 && (
            <Stack>
              <Title order={2} size="h4">Allowed modules & request limits</Title>
              <Checkbox.Group label="Modules this project may use later" description="Selecting a module does not start anything. Web, attack-surface, API and repository scanners are available."
                value={values.allowed_modules} onChange={(v) => set("allowed_modules", v as ScanModule[])}>
                <Stack mt={4} gap={6}>
                  {SCAN_MODULES.map((m) => (
                    <Checkbox key={m.value} value={m.value} label={m.label} />
                  ))}
                </Stack>
              </Checkbox.Group>
              {values.allowed_modules.includes("repo_scan") && (
                <TextInput
                  label="Repository path"
                  description="Absolute local filesystem path the repository scanner (Semgrep/Gitleaks/Trivy) will scan. Not fetched over the network — the application must already have read access to it."
                  placeholder="C:\path\to\repository"
                  value={values.repository_path}
                  onChange={(e) => set("repository_path", e.currentTarget.value)}
                  error={fieldError("repository_path", "repository_path")}
                />
              )}
              <Group grow align="flex-start">
                <NumberInput label="Requests per second (per host)" min={0.1} max={10} step={0.5} decimalScale={1} value={values.requests_per_second}
                  onChange={(v) => set("requests_per_second", Number(v) || 0.1)} error={serverFieldErrors["scan_policy.requests_per_second"]} />
                <NumberInput label="Max concurrency" min={1} max={8} value={values.max_concurrency}
                  onChange={(v) => set("max_concurrency", Number(v) || 1)} error={serverFieldErrors["scan_policy.max_concurrency"]} />
                <NumberInput label="Max duration (minutes)" min={1} max={480} value={values.max_duration_minutes}
                  onChange={(v) => set("max_duration_minutes", Number(v) || 1)} error={serverFieldErrors["scan_policy.max_duration_seconds"]} />
              </Group>
              <Group grow align="flex-start">
                <NumberInput label="Connect timeout (s)" min={1} max={30} value={values.connect_timeout_seconds}
                  onChange={(v) => set("connect_timeout_seconds", Number(v) || 1)} />
                <NumberInput label="Read timeout (s)" min={1} max={60} value={values.read_timeout_seconds}
                  onChange={(v) => set("read_timeout_seconds", Number(v) || 1)} />
                <NumberInput label="Max crawl depth" min={0} max={10} value={values.max_crawl_depth}
                  onChange={(v) => set("max_crawl_depth", Number(v) || 0)} />
                <NumberInput label="Max pages" min={1} max={2000} value={values.max_pages}
                  onChange={(v) => set("max_pages", Number(v) || 1)} />
              </Group>
              <NumberInput label="Evidence retention (days)" description="Leave empty to keep evidence until manually deleted" min={1} max={3650}
                value={values.evidence_retention_days} onChange={(v) => set("evidence_retention_days", v === "" ? "" : Number(v))} allowDecimal={false} w={280} />
              <Text size="sm" c="dimmed">Active injection probes (SQLi/XSS) are not built into the web scanner (safe mode); API write, IDOR and rate-limit probes stay disabled by default and require explicit test identities, fixtures and acknowledgement.</Text>
            </Stack>
          )}

          {active === 4 && preview?.scope && (
            <Stack>
              <Title order={2} size="h4">Review</Title>
              <Text size="sm"><strong>{values.name}</strong> for {values.client_name}</Text>
              <Text size="sm">
                Authorization:{" "}
                {existing && !authorizationTouched ? "unchanged" : values.includeAuthorization ? `${values.authorized_by} · ${values.window_start} → ${values.window_end} (local)` : "none (project will be flagged)"}
              </Text>
              <ScopeSummary scope={preview.scope} />
              <Text size="sm">
                Limits: {values.requests_per_second} req/s · concurrency {values.max_concurrency} · {values.max_pages} pages · {values.max_duration_minutes} min
              </Text>
              {values.repository_path && (
                <Text size="sm">Repository path: {values.repository_path}</Text>
              )}
            </Stack>
          )}

          {saveError && <ErrorAlert error={saveError} title="Could not save the project" />}

          <Group justify="space-between" mt="xl">
            <Button variant="default" onClick={() => (active === 0 ? navigate(-1) : setActive(active - 1))}>
              {active === 0 ? "Cancel" : "Back"}
            </Button>
            {active < STEPS.length - 1 ? (
              <Button type="submit">Next</Button>
            ) : (
              <Button type="submit" loading={saving}>
                {existing ? "Save changes" : "Create project"}
              </Button>
            )}
          </Group>
        </form>
      </Card>
    </>
  );
}

function PreviewTable({ preview }: { preview: ScopePreviewResponse }) {
  return (
    <Stack gap="xs">
      {preview.notes.map((n) => (
        <Text size="xs" c="dimmed" key={n}>{n}</Text>
      ))}
      <BlockedRangesTable ranges={preview.blocked_ranges} />
      <Table.ScrollContainer minWidth={600}>
        <Table aria-label="Scope preview">
          <Table.Thead>
            <Table.Tr>
              <Table.Th scope="col">Field</Table.Th>
              <Table.Th scope="col">Input</Table.Th>
              <Table.Th scope="col">Interpreted as</Table.Th>
              <Table.Th scope="col">Result</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {preview.entries.map((e, i) => (
              <Table.Tr key={`${e.field}-${i}`}>
                <Table.Td>{e.field}</Table.Td>
                <Table.Td style={{ wordBreak: "break-all" }}>{e.input || "—"}</Table.Td>
                <Table.Td>{e.normalized ? `${e.kind}: ${e.normalized}` : e.kind}</Table.Td>
                <Table.Td>
                  {e.error ? (
                    <Text size="sm" c="red.8">✕ {e.error}</Text>
                  ) : (
                    <Stack gap={2}>
                      <Text size="sm">✓ OK</Text>
                      {e.warnings.map((w) => (
                        <Text size="xs" c="orange.8" key={w}>! {w}</Text>
                      ))}
                    </Stack>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Stack>
  );
}
