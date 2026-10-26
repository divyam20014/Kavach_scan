import { Alert, Badge, Button, Card, Checkbox, Code, Group, Modal, Radio, Stack, Text, TextInput, Textarea, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { useApiScanPlan, useKillSwitch, useModules, useScopePolicy, useSetKillSwitch, useStartScan, useSurfaceProfile, useWebScanProfile } from "../api/hooks";
import type { Project, ScanModule } from "../api/types";
import { humanize, splitLines } from "../lib/format";
import { ErrorAlert, QueryState } from "./QueryState";
import { DEFAULT_WEB_OPTIONS, WebProfileSummary, WebScanOptions, webParams, type WebOptions } from "./WebScanProfile";
import { DEFAULT_SURFACE_OPTIONS, SurfaceProfileSummary, SurfaceScanOptions, surfaceParams, type SurfaceOptions } from "./SurfaceScanProfile";
import { DEFAULT_API_OPTIONS, ApiScanOptions, apiParams, type ApiOptions } from "./ApiScanProfile";
import { DEFAULT_REPO_SCAN_OPTIONS, RepoScanOptionsPanel, repoScanParams, type RepoScanOptions } from "./RepoScanProfile";

/** Start-a-job panel with an explicit confirmation step (MASTER_SPEC §4.1). */
export function StartJobCard({ project }: { project: Project }) {
  const modules = useModules();
  const policy = useScopePolicy(project.project_id);
  const killSwitch = useKillSwitch();
  const start = useStartScan(project.project_id);
  const navigate = useNavigate();
  const [module, setModule] = useState<ScanModule | "">("");
  const [targets, setTargets] = useState("");
  const [reviewing, setReviewing] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  // One idempotency key per confirmation dialog: double-clicking "Start job" cannot create two jobs.
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const gateOpen = policy.data?.can_start_active_work && !killSwitch.data?.engaged;
  const p = project.scan_policy;
  const [webOptions, setWebOptions] = useState<WebOptions>(DEFAULT_WEB_OPTIONS);
  const [surfaceOptions, setSurfaceOptions] = useState<SurfaceOptions>(DEFAULT_SURFACE_OPTIONS);
  const [apiOptions, setApiOptions] = useState<ApiOptions>(DEFAULT_API_OPTIONS);
  const [repoScanOptions, setRepoScanOptions] = useState<RepoScanOptions>(DEFAULT_REPO_SCAN_OPTIONS);
  const isWeb = module === "web_app";
  const isSurface = module === "attack_surface";
  const isApi = module === "api_security";
  const isRepoScan = module === "repo_scan";
  const targetList = splitLines(targets);
  const parameters = isWeb ? webParams(webOptions) : isSurface ? surfaceParams(surfaceOptions) : isApi ? apiParams(apiOptions) : isRepoScan ? repoScanParams(repoScanOptions) : {};
  const profile = useWebScanProfile(project.project_id, parameters, isWeb);
  const surfaceProfile = useSurfaceProfile(
    project.project_id,
    { ...surfaceParams(surfaceOptions), targets: targetList } as Record<string, string | number | boolean | string[] | undefined>,
    isSurface && targetList.length > 0,
  );
  const apiPlan = useApiScanPlan(project.project_id, parameters as Record<string, unknown>, isApi && Boolean(apiOptions.import_id));
  const profileInvalid =
    (isWeb && (profile.data?.problems.length ?? 0) > 0) ||
    (isSurface && ((surfaceProfile.data?.problems.length ?? 0) > 0 || (surfaceProfile.data?.target_problems.length ?? 0) > 0)) ||
    (isApi && (!apiOptions.import_id || (apiPlan.data?.problems.length ?? 0) > 0 || (!apiOptions.inventory_only && !apiPlan.data?.server_in_scope))) ||
    (isRepoScan && !project.repository_path);

  const submit = () =>
    start.mutate(
      {
        module: module as ScanModule,
        targets: isApi ? ["api-spec"] : isRepoScan ? ["repo-scan"] : splitLines(targets),
        parameters,
        confirmed,
        idempotency_key: idempotencyKey,
      },
      {
        onSuccess: (scan) => {
          setReviewing(false);
          notifications.show({ color: "green", message: "Job queued" });
          navigate(`/projects/${scan.project_id}/scans/${scan.scan_id}`);
        },
      },
    );

  return (
    <Card withBorder component="section" aria-labelledby="start-h">
      <Title order={2} size="h4" id="start-h" mb="sm">Start a job</Title>
      <QueryState query={modules}>
        {(list) => (
          <Stack gap="sm">
            {!gateOpen && (
              <Alert color="red" variant="light" role="note">
                {killSwitch.data?.engaged ? "The global kill switch is engaged: no jobs can start." : `Active work is blocked: ${policy.data?.authorization.message ?? "checking authorization…"}`}
              </Alert>
            )}
            <Radio.Group label="Module" value={module} onChange={(v) => setModule(v as ScanModule)}>
              <Stack gap={6} mt={4}>
                {list.map((m) => (
                  <Radio key={m.module} value={m.module} disabled={!m.available}
                    label={m.available ? m.label : `${m.label} — unavailable: ${m.reason}`} />
                ))}
              </Stack>
            </Radio.Group>
            {isApi ? (
              <Text size="sm" c="dimmed">Targets come from the selected API spec's in-scope server; no target list is needed.</Text>
            ) : isRepoScan ? (
              <Text size="sm" c="dimmed">The target is this project's own configured repository path; no target list is needed.</Text>
            ) : (
              <Textarea label={isSurface ? "Targets (one in-scope host or authorized root domain per line)" : "Targets (one URL per line, must be in scope)"}
                value={targets} onChange={(e) => setTargets(e.currentTarget.value)}
                autosize minRows={2} placeholder={isSurface ? "example.com" : "https://app.example.com/"} />
            )}
            {isWeb && (
              <Card withBorder padding="sm" component="section" aria-labelledby="web-profile-h">
                <Title order={3} size="h5" id="web-profile-h" mb="xs">Web scan profile</Title>
                <Stack gap="sm">
                  <WebScanOptions value={webOptions} onChange={setWebOptions} limits={{ pages: p.max_pages, depth: p.max_crawl_depth }} />
                  <QueryState query={profile} loadingLabel="Loading scan profile…">
                    {(preview) => <WebProfileSummary preview={preview} />}
                  </QueryState>
                </Stack>
              </Card>
            )}
            {isApi && (
              <Card withBorder padding="sm" component="section" aria-labelledby="api-profile-h">
                <Title order={3} size="h5" id="api-profile-h" mb="xs">API security scan</Title>
                <Stack gap="sm">
                  <ApiScanOptions projectId={project.project_id} value={apiOptions} onChange={setApiOptions} />
                  {apiPlan.data && apiPlan.data.problems.length > 0 && (
                    <Alert color="red" role="alert" title="Fix before starting">
                      {apiPlan.data.problems.map((pr) => <Text size="sm" key={pr}>✕ {pr}</Text>)}
                    </Alert>
                  )}
                  {apiPlan.data && !apiOptions.inventory_only && (
                    <Text size="sm">Server: {apiPlan.data.server_in_scope ? "in scope" : <Text span c="red">out of scope — {apiPlan.data.server_reason}</Text>}</Text>
                  )}
                  {apiPlan.data && <Text size="sm" c="dimmed">{apiPlan.data.operations_total} operations · {apiOptions.inventory_only ? "inventory only (no requests)" : "bounded network checks"}</Text>}
                </Stack>
              </Card>
            )}
            {isRepoScan && (
              <Card withBorder padding="sm" component="section" aria-labelledby="repo-scan-profile-h">
                <Title order={3} size="h5" id="repo-scan-profile-h" mb="xs">Repository scan</Title>
                <RepoScanOptionsPanel value={repoScanOptions} onChange={setRepoScanOptions} repositoryPath={project.repository_path} />
              </Card>
            )}
            {isSurface && (
              <Card withBorder padding="sm" component="section" aria-labelledby="surface-profile-h">
                <Title order={3} size="h5" id="surface-profile-h" mb="xs">Attack surface profile</Title>
                <Stack gap="sm">
                  <SurfaceScanOptions value={surfaceOptions} onChange={setSurfaceOptions} />
                  {targetList.length === 0 ? (
                    <Text size="sm" c="dimmed">Enter at least one in-scope host or authorized root domain above to preview the plan.</Text>
                  ) : (
                    <QueryState query={surfaceProfile} loadingLabel="Loading surface plan…">
                      {(preview) => <SurfaceProfileSummary preview={preview} />}
                    </QueryState>
                  )}
                </Stack>
              </Card>
            )}
            <Button w="fit-content" disabled={!module || (!isApi && !isRepoScan && !splitLines(targets).length) || !gateOpen || profileInvalid}
              onClick={() => { setConfirmed(false); start.reset(); setIdempotencyKey(`ui-${crypto.randomUUID()}`); setReviewing(true); }}>
              Review &amp; confirm…
            </Button>
          </Stack>
        )}
      </QueryState>

      <Modal opened={reviewing} onClose={() => setReviewing(false)} title="Confirm job start" centered size="lg">
        <Stack gap="sm">
          <Text size="sm">Module: <strong>{module ? humanize(module) : ""}</strong></Text>
          <div>
            <Text size="sm">Targets:</Text>
            {isRepoScan ? <Code>{project.repository_path}</Code> : splitLines(targets).map((t) => <Code key={t} mr={4}>{t}</Code>)}
          </div>
          <Text size="sm">
            Limits: {p.requests_per_second} req/s per host · concurrency {p.max_concurrency} · max {p.max_requests_per_target} requests per target ·
            max {Math.round(p.max_duration_seconds / 60)} min
          </Text>
          {isSurface && surfaceProfile.data && (
            <Text size="sm">
              Surface map: {surfaceProfile.data.profile.ports.tested.length} port(s) via {surfaceProfile.data.profile.port_method} ·{" "}
              max {surfaceProfile.data.profile.max_hosts} hosts ·{" "}
              crt.sh {surfaceProfile.data.profile.sources.find((s) => s.name === "crtsh")?.enabled ? "on" : "off"}
            </Text>
          )}
          {isWeb && profile.data && (
            <>
              <Text size="sm">
                Web scan: safe mode {profile.data.profile.safe_mode ? "on (no injection test input is sent)" : "off"} ·{" "}
                {profile.data.profile.checks.filter((c) => c.enabled).length} check groups enabled ·{" "}
                {profile.data.profile.budgets.max_pages} pages max · depth {profile.data.profile.budgets.max_depth}
              </Text>
              {Object.keys(parameters).length > 0 && (
                <Text size="sm">Options recorded in the job manifest: {Object.entries(parameters).map(([k, v]) => <Code key={k} mr={4}>{k}={String(v)}</Code>)}</Text>
              )}
            </>
          )}
          {isRepoScan && (
            <Text size="sm">
              Engines: {repoScanOptions.engines.map((e) => (
                <Code key={e} mr={4}>{e}{repoScanOptions.docker_engines.includes(e) ? " (Docker)" : " (native)"}</Code>
              ))}
            </Text>
          )}
          <Text size="sm">
            {isRepoScan
              ? "This scan reads local files only; it makes no network requests to any target."
              : "Every request, redirect and resolved address is checked against the project scope; blocked targets receive no traffic."}
          </Text>
          <Checkbox label="I confirm these targets are in my authorized scope and I want to start this job." checked={confirmed}
            onChange={(e) => setConfirmed(e.currentTarget.checked)} />
          {start.isError && <ErrorAlert error={start.error} title="The job was not started" />}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setReviewing(false)}>Back</Button>
            <Button disabled={!confirmed} loading={start.isPending} onClick={submit}>Start job</Button>
          </Group>
        </Stack>
      </Modal>
    </Card>
  );
}

/** Header control for the global kill switch. */
export function KillSwitchControl() {
  const state = useKillSwitch();
  const set = useSetKillSwitch();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const engaged = state.data?.engaged ?? false;
  const toggle = () =>
    set.mutate(
      { engaged: !engaged, reason },
      {
        onSuccess: (s) => {
          setOpen(false);
          setReason("");
          notifications.show({ color: s.engaged ? "red" : "green", message: s.engaged ? "Kill switch engaged: all jobs are being stopped" : "Kill switch released" });
        },
        onError: (e) => notifications.show({ color: "red", message: e instanceof ApiError ? e.describe() : "Failed" }),
      },
    );
  return (
    <>
      <Group gap="xs">
        {engaged && <Badge color="red" variant="filled" leftSection={<span aria-hidden="true">■</span>}>Kill switch engaged</Badge>}
        <Button size="xs" color={engaged ? "gray" : "red"} variant={engaged ? "default" : "light"} onClick={() => setOpen(true)} disabled={state.isPending}>
          {engaged ? "Release kill switch…" : "Kill switch…"}
        </Button>
      </Group>
      <Modal opened={open} onClose={() => setOpen(false)} title={engaged ? "Release the kill switch?" : "Engage the global kill switch?"} centered>
        <Stack>
          <Text size="sm">
            {engaged ? "New jobs will be allowed to start again." : "All running and queued jobs are cancelled and no new jobs can start until it is released."}
          </Text>
          <TextInput label="Reason (recorded in the audit log)" value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setOpen(false)}>Cancel</Button>
            <Button color={engaged ? "blue" : "red"} disabled={reason.trim().length < 3} loading={set.isPending} onClick={toggle}>
              {engaged ? "Release" : "Engage kill switch"}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
