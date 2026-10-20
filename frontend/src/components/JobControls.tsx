import { Alert, Badge, Button, Card, Checkbox, Code, Group, Modal, Radio, Stack, Text, TextInput, Textarea, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { useKillSwitch, useModules, useScopePolicy, useSetKillSwitch, useStartScan, useWebScanProfile } from "../api/hooks";
import type { Project, ScanModule } from "../api/types";
import { humanize, splitLines } from "../lib/format";
import { ErrorAlert, QueryState } from "./QueryState";
import { DEFAULT_WEB_OPTIONS, WebProfileSummary, WebScanOptions, webParams, type WebOptions } from "./WebScanProfile";

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
  const isWeb = module === "web_app";
  const parameters = isWeb ? webParams(webOptions) : {};
  const profile = useWebScanProfile(project.project_id, parameters, isWeb);
  const profileInvalid = isWeb && (profile.data?.problems.length ?? 0) > 0;

  const submit = () =>
    start.mutate(
      { module: module as ScanModule, targets: splitLines(targets), parameters, confirmed, idempotency_key: idempotencyKey },
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
            <Textarea label="Targets (one URL per line, must be in scope)" value={targets} onChange={(e) => setTargets(e.currentTarget.value)}
              autosize minRows={2} placeholder="https://app.example.com/" />
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
            <Button w="fit-content" disabled={!module || !splitLines(targets).length || !gateOpen || profileInvalid}
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
            {splitLines(targets).map((t) => <Code key={t} mr={4}>{t}</Code>)}
          </div>
          <Text size="sm">
            Limits: {p.requests_per_second} req/s per host · concurrency {p.max_concurrency} · max {p.max_requests_per_target} requests per target ·
            max {Math.round(p.max_duration_seconds / 60)} min
          </Text>
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
          <Text size="sm">Every request, redirect and resolved address is checked against the project scope; blocked targets receive no traffic.</Text>
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
