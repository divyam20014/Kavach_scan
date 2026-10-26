import { Alert, Checkbox, Group, NumberInput, Select, Stack, Text } from "@mantine/core";
import type { ScanParams } from "../api/types";

export type RepoScanEngine = "semgrep" | "gitleaks" | "trivy";

export interface RepoScanOptions {
  engines: RepoScanEngine[];
  docker_engines: RepoScanEngine[];
  semgrep_config: string;
  semgrep_timeout_minutes: number;
  gitleaks_timeout_minutes: number;
  trivy_timeout_minutes: number;
}

export const DEFAULT_REPO_SCAN_OPTIONS: RepoScanOptions = {
  engines: ["semgrep"],
  docker_engines: [],
  semgrep_config: "p/security-audit",
  semgrep_timeout_minutes: 5,
  gitleaks_timeout_minutes: 5,
  trivy_timeout_minutes: 5,
};

const SEMGREP_CONFIGS = [
  "auto",
  "p/security-audit",
  "p/owasp-top-ten",
  "p/secrets",
  "p/python",
  "p/javascript",
  "p/default",
];

const ENGINES: { value: RepoScanEngine; label: string }[] = [
  { value: "semgrep", label: "Semgrep — static source-code security analysis" },
  { value: "gitleaks", label: "Gitleaks — repository secret scanning" },
  { value: "trivy", label: "Trivy — dependency/supply-chain vulnerability scanning (requires its vulnerability database to have been downloaded in Integrations)" },
];

/** Only values that differ from the backend's own defaults are sent, consistent with the
 * other scan-profile components' own convention. */
export function repoScanParams(o: RepoScanOptions): ScanParams {
  const p: ScanParams = { engines: o.engines };
  if (o.docker_engines.length) p.docker_engines = o.docker_engines;
  if (o.semgrep_config !== DEFAULT_REPO_SCAN_OPTIONS.semgrep_config) p.semgrep_config = o.semgrep_config;
  if (o.semgrep_timeout_minutes !== DEFAULT_REPO_SCAN_OPTIONS.semgrep_timeout_minutes) p.semgrep_timeout_minutes = o.semgrep_timeout_minutes;
  if (o.gitleaks_timeout_minutes !== DEFAULT_REPO_SCAN_OPTIONS.gitleaks_timeout_minutes) p.gitleaks_timeout_minutes = o.gitleaks_timeout_minutes;
  if (o.trivy_timeout_minutes !== DEFAULT_REPO_SCAN_OPTIONS.trivy_timeout_minutes) p.trivy_timeout_minutes = o.trivy_timeout_minutes;
  return p;
}

export function RepoScanOptionsPanel({
  value,
  onChange,
  repositoryPath,
}: {
  value: RepoScanOptions;
  onChange: (v: RepoScanOptions) => void;
  repositoryPath: string;
}) {
  const set = <K extends keyof RepoScanOptions>(k: K, v: RepoScanOptions[K]) => onChange({ ...value, [k]: v });
  return (
    <Stack gap="xs" aria-label="Repository scan options" role="group">
      {!repositoryPath ? (
        <Alert color="red" variant="light" role="alert">
          This project has no repository path configured. Set one via "Edit project" before starting a repository scan.
        </Alert>
      ) : (
        <Text size="sm" c="dimmed">Scanning: <strong>{repositoryPath}</strong></Text>
      )}
      <div>
        <Text size="sm" fw={500} mb={4}>Engines</Text>
        <Stack gap={6}>
          {ENGINES.map((e) => {
            const checked = value.engines.includes(e.value);
            const viaDocker = value.docker_engines.includes(e.value);
            return (
              <div key={e.value}>
                <Checkbox
                  label={e.label}
                  checked={checked}
                  onChange={(ev) => {
                    const on = ev.currentTarget.checked;
                    const engines = on
                      ? [...value.engines, e.value]
                      : value.engines.filter((x) => x !== e.value);
                    const docker_engines = on
                      ? value.docker_engines
                      : value.docker_engines.filter((x) => x !== e.value);
                    onChange({
                      ...value,
                      engines: (engines.length ? engines : ["semgrep"]) as RepoScanEngine[],
                      docker_engines,
                    });
                  }}
                />
                {checked && (
                  <Checkbox
                    ml="xl"
                    mt={2}
                    size="xs"
                    label="Run via Docker (uses the pulled image instead of a native install — see Integrations)"
                    checked={viaDocker}
                    onChange={(ev) => {
                      const on = ev.currentTarget.checked;
                      set(
                        "docker_engines",
                        on
                          ? [...value.docker_engines, e.value]
                          : value.docker_engines.filter((x) => x !== e.value),
                      );
                    }}
                  />
                )}
              </div>
            );
          })}
        </Stack>
      </div>
      {value.engines.includes("semgrep") && (
        <Select
          label="Semgrep ruleset"
          data={SEMGREP_CONFIGS}
          value={value.semgrep_config}
          onChange={(v) => set("semgrep_config", v ?? DEFAULT_REPO_SCAN_OPTIONS.semgrep_config)}
        />
      )}
      <Group grow align="flex-start">
        {value.engines.includes("semgrep") && (
          <NumberInput label="Semgrep timeout (min)" min={1} max={60} value={value.semgrep_timeout_minutes}
            onChange={(v) => set("semgrep_timeout_minutes", Number(v) || 5)} />
        )}
        {value.engines.includes("gitleaks") && (
          <NumberInput label="Gitleaks timeout (min)" min={1} max={60} value={value.gitleaks_timeout_minutes}
            onChange={(v) => set("gitleaks_timeout_minutes", Number(v) || 5)} />
        )}
        {value.engines.includes("trivy") && (
          <NumberInput label="Trivy timeout (min)" min={1} max={60} value={value.trivy_timeout_minutes}
            onChange={(v) => set("trivy_timeout_minutes", Number(v) || 5)} />
        )}
      </Group>
    </Stack>
  );
}
