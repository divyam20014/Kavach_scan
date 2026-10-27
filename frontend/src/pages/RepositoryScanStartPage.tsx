import { Alert, Button, Card, Checkbox, Group, SegmentedControl, Stack, Text, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useCreateAndStartRepoScan } from "../api/hooks";
import type { RepoScanProjectCreate, StartScanRequest } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ErrorAlert } from "../components/QueryState";
import { DEFAULT_REPO_SCAN_OPTIONS, RepoScanOptionsPanel, repoScanParams, type RepoScanOptions } from "../components/RepoScanProfile";
import { isoToLocalInput, localInputToIso } from "../lib/format";

/** A standalone, one-page "enter a repo, configure, go" flow (operator-requested: repository
 * scanning should not require walking through the generic project wizard's network-scope
 * step, which is meaningless for a module that only ever reads local files / clones a repo).
 * Creates a scope-less repo_scan-only project behind the scenes, then starts the scan on it
 * immediately -- the operator never sees a project list entry for it until after the scan is
 * already queued, at which point it's just an ordinary project like any other. */

const now = () => new Date();
const plusDays = (d: Date, days: number) => new Date(d.getTime() + days * 86_400_000);

interface FormValues {
  name: string;
  repository_source: "path" | "url";
  repository_path: string;
  repository_url: string;
  repository_credential_alias: string;
  organization: string;
  target_owner: string;
  authorized_by: string;
  window_start: string;
  window_end: string;
  attestation: boolean;
}

function emptyValues(): FormValues {
  const start = now();
  return {
    name: "",
    repository_source: "path",
    repository_path: "",
    repository_url: "",
    repository_credential_alias: "",
    organization: "",
    target_owner: "",
    authorized_by: "",
    window_start: isoToLocalInput(start.toISOString()),
    window_end: isoToLocalInput(plusDays(start, 90).toISOString()),
    attestation: false,
  };
}

export function RepositoryScanStartPage() {
  const [v, setV] = useState<FormValues>(emptyValues());
  const [repoScanOptions, setRepoScanOptions] = useState<RepoScanOptions>(DEFAULT_REPO_SCAN_OPTIONS);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const create = useCreateAndStartRepoScan();
  const navigate = useNavigate();

  const set = <K extends keyof FormValues>(k: K, val: FormValues[K]) => setV({ ...v, [k]: val });

  const validate = (): Record<string, string> => {
    const e: Record<string, string> = {};
    if (!v.name.trim()) e.name = "Name is required";
    if (v.repository_source === "path" && !v.repository_path.trim()) e.repository_path = "Repository path is required";
    if (v.repository_source === "url" && !v.repository_url.trim()) e.repository_url = "Repository URL is required";
    if (!v.organization.trim()) e.organization = "Organization is required";
    if (!v.target_owner.trim()) e.target_owner = "Target owner is required";
    if (!v.authorized_by.trim()) e.authorized_by = "Authorized-by is required";
    if (!v.window_start) e.window_start = "Start of the authorization window is required";
    if (!v.window_end) e.window_end = "End of the authorization window is required";
    if (v.window_start && v.window_end && new Date(v.window_end) <= new Date(v.window_start)) e.window_end = "End must be after start";
    if (!v.attestation) e.attestation = "You must attest that you hold this authorization";
    return e;
  };

  const submit = () => {
    const e = validate();
    setErrors(e);
    if (Object.keys(e).length > 0) return;

    const project: RepoScanProjectCreate = {
      name: v.name.trim(),
      client_name: v.name.trim(),
      authorization: {
        organization: v.organization.trim(),
        target_owner: v.target_owner.trim(),
        authorized_by: v.authorized_by.trim(),
        reference: "",
        window_start: localInputToIso(v.window_start),
        window_end: localInputToIso(v.window_end),
        notes: "",
        attestation: v.attestation,
      },
      repository_path: v.repository_source === "path" ? v.repository_path.trim() : "",
      repository_url: v.repository_source === "url" ? v.repository_url.trim() : "",
      repository_credential_alias: v.repository_source === "url" ? v.repository_credential_alias.trim() : "",
      scan_policy: { allowed_modules: ["repo_scan"] },
    };
    const scan: StartScanRequest = {
      module: "repo_scan",
      targets: ["repo-scan"],
      parameters: repoScanParams(repoScanOptions),
      confirmed: true,
    };
    create.mutate(
      { project, scan },
      {
        onSuccess: ({ project: p, scan: s }) => {
          notifications.show({ color: "green", message: `Repository scan started for “${p.name}”` });
          navigate(`/projects/${p.project_id}/scans/${s.scan_id}`);
        },
      },
    );
  };

  return (
    <>
      <PageHeader
        title="Repository Scan"
        description="Scan a repository's source code directly — no network scope to configure, since this only ever reads local files or clones the repository itself."
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Repository Scan" }]}
      />
      <Card withBorder component="section" aria-labelledby="repo-scan-start-h" maw={720}>
        <Title order={2} size="h4" id="repo-scan-start-h" mb="sm">Start a repository scan</Title>
        <Stack gap="md">
          <TextInput label="Name" description="Used to identify this scan later (dashboard, findings, reports)." required
            value={v.name} error={errors.name} onChange={(e) => set("name", e.currentTarget.value)} />

          <div>
            <Text size="sm" fw={500} mb={4}>Repository</Text>
            <Stack gap="xs">
              <SegmentedControl value={v.repository_source} onChange={(x) => set("repository_source", x as "path" | "url")}
                data={[{ label: "Local path", value: "path" }, { label: "Clone from a URL", value: "url" }]} />
              {v.repository_source === "path" ? (
                <TextInput label="Repository path" placeholder="D:\path\to\repo" required
                  value={v.repository_path} error={errors.repository_path} onChange={(e) => set("repository_path", e.currentTarget.value)} />
              ) : (
                <>
                  <TextInput label="Repository URL" placeholder="https://github.com/org/repo.git" required
                    value={v.repository_url} error={errors.repository_url} onChange={(e) => set("repository_url", e.currentTarget.value)} />
                  <TextInput label="Credential alias (optional)" description="e.g. env:MY_GIT_TOKEN — a reference only, never a raw secret."
                    value={v.repository_credential_alias} onChange={(e) => set("repository_credential_alias", e.currentTarget.value)} />
                </>
              )}
            </Stack>
          </div>

          <div>
            <Text size="sm" fw={500} mb={4}>Authorization</Text>
            <Stack gap="xs">
              <Group grow>
                <TextInput label="Organization / client" required value={v.organization} error={errors.organization}
                  onChange={(e) => set("organization", e.currentTarget.value)} />
                <TextInput label="Target owner" required value={v.target_owner} error={errors.target_owner}
                  onChange={(e) => set("target_owner", e.currentTarget.value)} />
              </Group>
              <TextInput label="Authorized by" required value={v.authorized_by} error={errors.authorized_by}
                onChange={(e) => set("authorized_by", e.currentTarget.value)} />
              <Group grow>
                <TextInput type="datetime-local" label="Window start (local time)" required value={v.window_start} error={errors.window_start}
                  onChange={(e) => set("window_start", e.currentTarget.value)} />
                <TextInput type="datetime-local" label="Window end (local time)" required value={v.window_end} error={errors.window_end}
                  onChange={(e) => set("window_end", e.currentTarget.value)} />
              </Group>
              <Checkbox label="Operator attestation: I confirm I am authorized to scan this repository's source code within this window."
                checked={v.attestation} error={errors.attestation} onChange={(e) => set("attestation", e.currentTarget.checked)} />
            </Stack>
          </div>

          <div>
            <Text size="sm" fw={500} mb={4}>Scan configuration</Text>
            <RepoScanOptionsPanel value={repoScanOptions} onChange={setRepoScanOptions}
              repositoryPath={v.repository_source === "path" ? v.repository_path : ""}
              repositoryUrl={v.repository_source === "url" ? v.repository_url : undefined} />
          </div>

          {create.isError && <ErrorAlert error={create.error} title="The scan was not started" />}
          <Alert color="blue" variant="light">
            This creates a new project scoped to this repository only (no network targets) and starts the scan immediately.
          </Alert>
          <Group justify="flex-end">
            <Button loading={create.isPending} onClick={submit}>Start scan</Button>
          </Group>
        </Stack>
      </Card>
    </>
  );
}
