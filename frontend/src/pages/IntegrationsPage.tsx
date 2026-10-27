import { Alert, Anchor, Badge, Button, Card, FileButton, Group, SimpleGrid, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useEffect, useState } from "react";
import { ApiError } from "../api/client";
import {
  useCveCatalog,
  useDeleteCveCatalog,
  useDockerImageStatus,
  useDownloadTrivyChecks,
  useDownloadTrivyDb,
  useImportCveCatalog,
  useIntegrationSelftest,
  useIntegrations,
  usePullDockerImage,
  useSettings,
  useTrivyChecksStatus,
  useTrivyDbStatus,
  useUpdateSettings,
} from "../api/hooks";
import type { IntegrationStatus } from "../api/types";
import { PageHeader } from "../components/PageHeader";
import { ErrorAlert, Loading, QueryState } from "../components/QueryState";
import { IntegrationStatusLabel } from "../components/StatusLabel";
import { formatDateTime } from "../lib/format";

export function IntegrationsPage() {
  const integrations = useIntegrations();
  return (
    <>
      <PageHeader
        title="Integrations & CVE catalog"
        description="Optional external tools and the local CVE catalog. Nothing here is ever contacted automatically, and a missing tool never produces a false pass."
        crumbs={[{ label: "Dashboard", to: "/" }, { label: "Settings & storage", to: "/settings" }, { label: "Integrations" }]}
      />
      <Stack gap="md">
        <QueryState query={integrations} loadingLabel="Checking installed tools…">
          {(statuses) => (
            <SimpleGrid cols={{ base: 1, md: 2 }}>
              {statuses.map((s) => (
                <ToolCard key={s.id} status={s} />
              ))}
            </SimpleGrid>
          )}
        </QueryState>

        <CveCatalogCard />
        <TrivyDbCard />
        <TrivyChecksCard />
        <DockerImagesCard />
        <ToolPathSettingsCard />
      </Stack>
    </>
  );
}

function ToolCard({ status: listStatus }: { status: IntegrationStatus }) {
  const selftest = useIntegrationSelftest();
  // `GET /api/integrations` is detection-only and never reports "verified" (running a
  // subprocess just to answer a list request would violate "no active target traffic on
  // page load"); a self-test's own response is the only source of a "verified" status, so
  // its result is kept here for this tool for the rest of the page's session.
  const [lastSelftest, setLastSelftest] = useState<IntegrationStatus | null>(null);
  const status = lastSelftest ?? listStatus;
  const run = () =>
    selftest.mutate(listStatus.id, {
      onSuccess: (result) => setLastSelftest(result),
      onError: (e) => notifications.show({ color: "red", title: "Self-test failed to run", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
    });
  return (
    <Card withBorder component="section" aria-labelledby={`tool-${status.id}-h`}>
      <Group justify="space-between" mb="xs">
        <Title order={2} size="h4" id={`tool-${status.id}-h`}>{status.label}</Title>
        <IntegrationStatusLabel status={status.status} />
      </Group>
      <Text size="sm" c="dimmed" mb="xs">{status.capability}</Text>
      <Table variant="vertical" mb="xs">
        <Table.Tbody>
          <Table.Tr><Table.Th w={140}>Configured path</Table.Th><Table.Td>{status.configured_path || "— (auto-detect)"}</Table.Td></Table.Tr>
          <Table.Tr><Table.Th>Detected at</Table.Th><Table.Td>{status.detected_path || "not found"}</Table.Td></Table.Tr>
          {status.version && <Table.Tr><Table.Th>Version</Table.Th><Table.Td>{status.version}</Table.Td></Table.Tr>}
          <Table.Tr>
            <Table.Th>Last used</Table.Th>
            <Table.Td>
              {status.last_used
                ? `${status.last_used.version} — ${formatDateTime(status.last_used.at)}`
                : "Never (no scan has recorded using this tool)"}
            </Table.Td>
          </Table.Tr>
        </Table.Tbody>
      </Table>
      {status.last_error && (
        <Alert color="red" role="alert" title="Last self-test error" mb="xs">
          {status.last_error}
        </Alert>
      )}
      <Text size="xs" c="dimmed" mb="sm">{status.troubleshooting}</Text>
      <Button size="xs" variant="default" onClick={run} loading={selftest.isPending}>
        Run self-test (version only, no target traffic)
      </Button>
    </Card>
  );
}

function CveCatalogCard() {
  const catalog = useCveCatalog();
  const importMutation = useImportCveCatalog();
  const deleteMutation = useDeleteCveCatalog();

  const onFile = (file: File | null) => {
    if (!file) return;
    importMutation.mutate(file, {
      onSuccess: () => notifications.show({ color: "green", message: "CVE catalog imported" }),
      onError: (e) => notifications.show({ color: "red", title: "Import failed", message: e instanceof ApiError ? e.describe() : "Invalid catalog file" }),
    });
  };
  const onDelete = () =>
    deleteMutation.mutate(undefined, {
      onSuccess: () => notifications.show({ color: "green", message: "CVE catalog removed" }),
    });

  return (
    <Card withBorder component="section" aria-labelledby="cve-h">
      <Title order={2} size="h4" id="cve-h" mb="sm">Local CVE catalog</Title>
      <Text size="sm" c="dimmed" mb="sm">
        Never fetched automatically. Import a JSON file mapping product/version ranges to CVE
        IDs; matching against detected components stays defensible — an ambiguous match is
        shown as a review candidate, never a confirmed vulnerability.
      </Text>
      {catalog.isPending ? (
        <Loading label="Checking catalog status…" />
      ) : catalog.isError ? (
        <ErrorAlert error={catalog.error} />
      ) : !catalog.data ? (
        <Text size="sm" c="dimmed" mb="sm">No catalog imported yet.</Text>
      ) : (
        <Stack gap="xs" mb="sm">
          <Group gap="xs">
            <Badge variant="outline">{catalog.data.source}</Badge>
            <Badge variant="outline">v{catalog.data.catalog_version}</Badge>
            <Badge variant="outline">{catalog.data.entry_count} entries</Badge>
            {catalog.data.is_stale && <Badge color="yellow">Stale (&gt;{catalog.data.stale_after_days}d old)</Badge>}
          </Group>
          <Text size="xs" c="dimmed">
            Imported {formatDateTime(catalog.data.imported_at)} · parser {catalog.data.parser_version} · sha256 {catalog.data.file_sha256.slice(0, 16)}…
          </Text>
          {catalog.data.warnings.length > 0 && (
            <Text size="xs" c="dimmed">{catalog.data.warnings.length} entries were skipped on import (malformed).</Text>
          )}
        </Stack>
      )}
      <Group>
        <FileButton onChange={onFile} accept="application/json,.json">
          {(props) => <Button {...props} variant="default" loading={importMutation.isPending}>Import catalog file…</Button>}
        </FileButton>
        {catalog.data && (
          <Button color="red" variant="light" onClick={onDelete} loading={deleteMutation.isPending}>
            Remove catalog
          </Button>
        )}
      </Group>
    </Card>
  );
}

function TrivyDbCard() {
  const status = useTrivyDbStatus();
  const downloadMutation = useDownloadTrivyDb();

  const onDownload = () =>
    downloadMutation.mutate(undefined, {
      onSuccess: () => notifications.show({ color: "green", message: "Trivy vulnerability database downloaded" }),
      onError: (e) => notifications.show({ color: "red", title: "Download failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
    });

  return (
    <Card withBorder component="section" aria-labelledby="trivy-db-h">
      <Title order={2} size="h4" id="trivy-db-h" mb="sm">Trivy vulnerability database</Title>
      <Text size="sm" c="dimmed" mb="sm">
        Never downloaded automatically by a scan. This is an explicit, one-time action (about
        1.6 GB) — a repository scan using the Trivy engine is rejected until this has been done.
      </Text>
      {status.isPending ? (
        <Loading label="Checking database status…" />
      ) : status.isError ? (
        <ErrorAlert error={status.error} />
      ) : !status.data ? (
        <Text size="sm" c="dimmed" mb="sm">Not downloaded yet.</Text>
      ) : (
        <Stack gap="xs" mb="sm">
          <Group gap="xs">
            <Badge variant="outline">Trivy {status.data.trivy_version}</Badge>
            <Badge variant="outline">{(status.data.size_bytes / (1024 * 1024 * 1024)).toFixed(2)} GB</Badge>
          </Group>
          <Text size="xs" c="dimmed">Downloaded {formatDateTime(status.data.downloaded_at)}</Text>
        </Stack>
      )}
      <Button variant="default" onClick={onDownload} loading={downloadMutation.isPending}>
        {status.data ? "Re-download database" : "Download database…"}
      </Button>
    </Card>
  );
}

function TrivyChecksCard() {
  const status = useTrivyChecksStatus();
  const downloadMutation = useDownloadTrivyChecks();

  const onDownload = () =>
    downloadMutation.mutate(undefined, {
      onSuccess: () => notifications.show({ color: "green", message: "Trivy checks bundle downloaded" }),
      onError: (e) => notifications.show({ color: "red", title: "Download failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
    });

  return (
    <Card withBorder component="section" aria-labelledby="trivy-checks-h">
      <Title order={2} size="h4" id="trivy-checks-h" mb="sm">Trivy IaC/misconfiguration checks bundle</Title>
      <Text size="sm" c="dimmed" mb="sm">
        A separate, independent download from the vulnerability database above (about 235 KB). Never
        downloaded automatically by a scan — a repository scan with the IaC option enabled is rejected
        until this has been done.
      </Text>
      {status.isPending ? (
        <Loading label="Checking checks-bundle status…" />
      ) : status.isError ? (
        <ErrorAlert error={status.error} />
      ) : !status.data ? (
        <Text size="sm" c="dimmed" mb="sm">Not downloaded yet.</Text>
      ) : (
        <Stack gap="xs" mb="sm">
          <Group gap="xs">
            <Badge variant="outline">Trivy {status.data.trivy_version}</Badge>
            <Badge variant="outline">{(status.data.size_bytes / 1024).toFixed(0)} KB</Badge>
          </Group>
          <Text size="xs" c="dimmed">Downloaded {formatDateTime(status.data.downloaded_at)}</Text>
        </Stack>
      )}
      <Button variant="default" onClick={onDownload} loading={downloadMutation.isPending}>
        {status.data ? "Re-download checks bundle" : "Download checks bundle…"}
      </Button>
    </Card>
  );
}

const DOCKER_ENGINES: { value: "semgrep" | "gitleaks" | "trivy"; label: string }[] = [
  { value: "semgrep", label: "Semgrep" },
  { value: "gitleaks", label: "Gitleaks" },
  { value: "trivy", label: "Trivy" },
];

function DockerEngineImageRow({ engine, label }: { engine: "semgrep" | "gitleaks" | "trivy"; label: string }) {
  const status = useDockerImageStatus(engine);
  const pullMutation = usePullDockerImage(engine);

  const onPull = () =>
    pullMutation.mutate(undefined, {
      onSuccess: () => notifications.show({ color: "green", message: `${label} Docker image pulled` }),
      onError: (e) => notifications.show({ color: "red", title: "Pull failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
    });

  return (
    <Group justify="space-between" wrap="wrap" py="xs">
      <div>
        <Text size="sm" fw={500}>{label}</Text>
        {status.isPending ? (
          <Loading label="Checking image status…" />
        ) : status.isError ? (
          <ErrorAlert error={status.error} />
        ) : !status.data ? (
          <Text size="xs" c="dimmed">Not pulled yet.</Text>
        ) : (
          <Group gap="xs">
            <Badge variant="outline">{status.data.image}</Badge>
            <Badge variant="outline">{(status.data.size_bytes / (1024 * 1024)).toFixed(0)} MB</Badge>
            <Text size="xs" c="dimmed">verified {status.data.verified_version} · pulled {formatDateTime(status.data.pulled_at)}</Text>
          </Group>
        )}
      </div>
      <Button variant="default" size="xs" onClick={onPull} loading={pullMutation.isPending}>
        {status.data ? "Re-pull image" : "Pull image…"}
      </Button>
    </Group>
  );
}

function DockerImagesCard() {
  return (
    <Card withBorder component="section" aria-labelledby="docker-images-h">
      <Title order={2} size="h4" id="docker-images-h" mb="sm">Docker images (optional, per engine)</Title>
      <Text size="sm" c="dimmed" mb="sm">
        An alternative to installing Semgrep/Gitleaks/Trivy locally — pull a pinned, versioned
        image once, per engine. Never pulled automatically by a scan. Requires Docker (see above).
      </Text>
      <Stack gap={0}>
        {DOCKER_ENGINES.map((e, i) => (
          <div key={e.value} style={i > 0 ? { borderTop: "1px solid var(--mantine-color-gray-3)" } : undefined}>
            <DockerEngineImageRow engine={e.value} label={e.label} />
          </div>
        ))}
      </Stack>
    </Card>
  );
}

function ToolPathSettingsCard() {
  const settings = useSettings();
  const update = useUpdateSettings();
  const [nmapPath, setNmapPath] = useState("");
  const [sslyzePath, setSslyzePath] = useState("");
  const [testsslPath, setTestsslPath] = useState("");
  const [zapPath, setZapPath] = useState("");
  const [semgrepPath, setSemgrepPath] = useState("");
  const [gitleaksPath, setGitleaksPath] = useState("");
  const [trivyPath, setTrivyPath] = useState("");
  const [dockerPath, setDockerPath] = useState("");
  const [gitPath, setGitPath] = useState("");
  const [credentialAlias, setCredentialAlias] = useState("");
  const [loadedRevision, setLoadedRevision] = useState<number | null>(null);

  // Pre-fill the draft fields from the loaded settings exactly once per fetch, so saving
  // without touching a field preserves its current value instead of blanking it out.
  useEffect(() => {
    if (settings.data && settings.data.revision !== loadedRevision) {
      setNmapPath(settings.data.integrations.nmap_path);
      setSslyzePath(settings.data.integrations.sslyze_path);
      setTestsslPath(settings.data.integrations.testssl_path);
      setZapPath(settings.data.integrations.zap_path);
      setSemgrepPath(settings.data.integrations.semgrep_path);
      setGitleaksPath(settings.data.integrations.gitleaks_path);
      setTrivyPath(settings.data.integrations.trivy_path);
      setDockerPath(settings.data.integrations.docker_path);
      setGitPath(settings.data.integrations.git_path);
      setLoadedRevision(settings.data.revision);
    }
  }, [settings.data, loadedRevision]);

  const save = () => {
    update.mutate(
      {
        expected_revision: settings.data?.revision,
        integrations: {
          nmap_path: nmapPath,
          sslyze_path: sslyzePath,
          testssl_path: testsslPath,
          zap_path: zapPath,
          semgrep_path: semgrepPath,
          gitleaks_path: gitleaksPath,
          trivy_path: trivyPath,
          docker_path: dockerPath,
          git_path: gitPath,
          ...(credentialAlias ? { online_lookup_credential_alias: credentialAlias } : {}),
        },
      },
      {
        onSuccess: () => {
          notifications.show({ color: "green", message: "Settings saved" });
          setCredentialAlias("");
        },
        onError: (e) => notifications.show({ color: "red", title: "Save failed", message: e instanceof ApiError ? e.describe() : "Unexpected error" }),
      },
    );
  };

  return (
    <Card withBorder component="section" aria-labelledby="tool-paths-h">
      <Title order={2} size="h4" id="tool-paths-h" mb="sm">Tool path overrides</Title>
      <Text size="sm" c="dimmed" mb="sm">
        Leave blank to auto-detect from PATH. Paths must be absolute.
      </Text>
      <QueryState query={settings} loadingLabel="Loading settings…">
        {(current) => (
          <Stack gap="sm">
            <TextInput
              label="Nmap path" placeholder="auto-detect"
              value={nmapPath} onChange={(e) => setNmapPath(e.currentTarget.value)}
            />
            <TextInput
              label="sslyze path" placeholder="auto-detect"
              value={sslyzePath} onChange={(e) => setSslyzePath(e.currentTarget.value)}
            />
            <TextInput
              label="testssl.sh path" placeholder="auto-detect"
              value={testsslPath} onChange={(e) => setTestsslPath(e.currentTarget.value)}
            />
            <TextInput
              label="ZAP path"
              description="The ZAP install directory, or a specific zap-*.jar file. Leave blank to check common install locations (ZAP is not registered on PATH)."
              placeholder="auto-detect"
              value={zapPath} onChange={(e) => setZapPath(e.currentTarget.value)}
            />
            <TextInput
              label="Semgrep path"
              description="A specific semgrep executable. Leave blank to use the one on PATH."
              placeholder="auto-detect"
              value={semgrepPath} onChange={(e) => setSemgrepPath(e.currentTarget.value)}
            />
            <TextInput
              label="Gitleaks path"
              description="A specific gitleaks executable. Leave blank to use the one on PATH."
              placeholder="auto-detect"
              value={gitleaksPath} onChange={(e) => setGitleaksPath(e.currentTarget.value)}
            />
            <TextInput
              label="Trivy path"
              description="A specific trivy executable. Leave blank to use the one on PATH."
              placeholder="auto-detect"
              value={trivyPath} onChange={(e) => setTrivyPath(e.currentTarget.value)}
            />
            <TextInput
              label="Docker path"
              description="A specific docker CLI executable. Leave blank to use the one on PATH."
              placeholder="auto-detect"
              value={dockerPath} onChange={(e) => setDockerPath(e.currentTarget.value)}
            />
            <TextInput
              label="Git path"
              description="A specific git executable. Leave blank to use the one on PATH."
              placeholder="auto-detect"
              value={gitPath} onChange={(e) => setGitPath(e.currentTarget.value)}
            />
            <TextInput
              type="password"
              label="Online lookup credential (write-only)"
              description='Reserved for a future opt-in online data source. Must be a reference like "env:NAME" or "keychain:NAME" — never a raw secret. Left blank, nothing is changed; this value is never shown once saved.'
              placeholder={current.integrations.online_lookup_credential_alias ? "•••• (already set)" : "env:NAME"}
              value={credentialAlias} onChange={(e) => setCredentialAlias(e.currentTarget.value)}
            />
            <Group>
              <Button onClick={save} loading={update.isPending} w="fit-content">Save</Button>
              <Anchor size="sm" href="https://nvd.nist.gov" target="_blank" rel="noreferrer" c="dimmed">
                No online lookup is active in this build
              </Anchor>
            </Group>
          </Stack>
        )}
      </QueryState>
    </Card>
  );
}
