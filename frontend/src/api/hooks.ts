import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, request } from "./client";
import type {
  Asset,
  EventPage,
  KillSwitchState,
  ManagerStatus,
  ModuleAvailability,
  ScanDetail,
  ScanParams,
  StartScanRequest,
  SurfaceProfilePreview,
  SurfaceView,
  WebProfilePreview,
  InternalOverrideRequest,
  ScopeCheckResponse,
  ScopePolicyView,
  AuditPage,
  DashboardSummary,
  DeletionImpact,
  Finding,
  Page,
  Project,
  ProjectCreate,
  ProjectOverview,
  ProjectUpdate,
  ScanJob,
  ScopePreviewRequest,
  ScopePreviewResponse,
  StorageDiagnostics,
  VersionInfo,
} from "./types";

export interface ListParams {
  q?: string;
  status?: string;
  sort?: string;
  order?: "asc" | "desc";
  offset?: number;
  limit?: number;
}

export const keys = {
  projects: (p: ListParams) => ["projects", p] as const,
  project: (id: string) => ["project", id] as const,
  dashboard: (projectId?: string) => ["dashboard", projectId ?? "all"] as const,
};

export function useProjects(params: ListParams) {
  return useQuery({ queryKey: keys.projects(params), queryFn: () => api.get<Page<ProjectOverview>>("/api/projects", { ...params }) });
}

export function useProject(projectId: string | undefined) {
  return useQuery({
    queryKey: keys.project(projectId ?? ""),
    queryFn: () => api.get<ProjectOverview>(`/api/projects/${encodeURIComponent(projectId ?? "")}`),
    enabled: Boolean(projectId),
  });
}

export function useDashboard(projectId?: string) {
  return useQuery({
    queryKey: keys.dashboard(projectId),
    queryFn: () => api.get<DashboardSummary>("/api/dashboard/summary", { project_id: projectId }),
  });
}

export function useRecords<T extends Finding | Asset | ScanJob>(
  kind: "findings" | "assets" | "scans",
  query: Record<string, string | string[] | number | undefined>,
) {
  return useQuery({ queryKey: [kind, query], queryFn: () => api.get<Page<T>>(`/api/${kind}`, query) });
}

export function useAudit(query: { project_id?: string; offset?: number; limit?: number }) {
  return useQuery({ queryKey: ["audit", query], queryFn: () => api.get<AuditPage>("/api/audit", query) });
}

export function useVersion() {
  return useQuery({ queryKey: ["version"], queryFn: () => api.get<VersionInfo>("/api/version"), staleTime: 60_000 });
}

export function useStorageDiagnostics() {
  return useQuery({ queryKey: ["diagnostics"], queryFn: () => api.get<StorageDiagnostics>("/api/diagnostics/storage") });
}

export function useDeletionImpact(projectId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["deletion-impact", projectId],
    queryFn: () => api.get<DeletionImpact>(`/api/projects/${encodeURIComponent(projectId)}/deletion-impact`),
    enabled,
  });
}

function useInvalidateAll() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries();
}

export function useCreateProject() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: (body: ProjectCreate) => api.post<Project>("/api/projects", body), onSuccess: invalidate });
}

export function useUpdateProject(projectId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (body: ProjectUpdate) => api.patch<Project>(`/api/projects/${encodeURIComponent(projectId)}`, body),
    onSuccess: invalidate,
  });
}

export function useDeleteProject(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (confirm: string) => api.delete<DeletionImpact>(`/api/projects/${encodeURIComponent(projectId)}`, { confirm }),
    onSuccess: () => {
      // Drop (not refetch) the deleted project's queries: refetching would 404, switch the
      // detail page to its error state and unmount the dialog before it can navigate away.
      qc.removeQueries({ queryKey: keys.project(projectId) });
      qc.removeQueries({ queryKey: ["deletion-impact", projectId] });
      return qc.invalidateQueries({ predicate: (q) => q.queryKey[0] !== "project" && q.queryKey[0] !== "deletion-impact" });
    },
  });
}

export function useScopePreview() {
  return useMutation({ mutationFn: (body: ScopePreviewRequest) => api.post<ScopePreviewResponse>("/api/scope/preview", body) });
}

export function useScopePolicy(projectId: string) {
  return useQuery({
    queryKey: ["scope-policy", projectId],
    queryFn: () => api.get<ScopePolicyView>(`/api/projects/${encodeURIComponent(projectId)}/scope/policy`),
  });
}

export function useScopeCheck(projectId: string) {
  return useMutation({
    mutationFn: (body: { url: string; resolved_ips: string[] }) =>
      api.post<ScopeCheckResponse>(`/api/projects/${encodeURIComponent(projectId)}/scope/check`, body),
  });
}

export function useSetOverride(projectId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (body: InternalOverrideRequest) =>
      request<Project>("PUT", `/api/projects/${encodeURIComponent(projectId)}/internal-override`, { body }),
    onSuccess: invalidate,
  });
}

export function useRemoveOverride(projectId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (expectedRevision: number) =>
      api.delete<Project>(`/api/projects/${encodeURIComponent(projectId)}/internal-override`, { expected_revision: expectedRevision }),
    onSuccess: invalidate,
  });
}

// ---------------------------------------------------------------- jobs (Phase 04)

const enc = encodeURIComponent;

export function useModules() {
  return useQuery({ queryKey: ["modules"], queryFn: () => api.get<ModuleAvailability[]>("/api/jobs/modules") });
}

export function useJobStatus() {
  return useQuery({ queryKey: ["job-status"], queryFn: () => api.get<ManagerStatus>("/api/jobs/status"), refetchInterval: 5000 });
}

export function useKillSwitch() {
  return useQuery({ queryKey: ["kill-switch"], queryFn: () => api.get<KillSwitchState>("/api/kill-switch"), refetchInterval: 5000 });
}

export function useSetKillSwitch() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (body: { engaged: boolean; reason: string }) => request<KillSwitchState>("PUT", "/api/kill-switch", { body }),
    onSuccess: invalidate,
  });
}

export function useStartScan(projectId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (body: StartScanRequest) => api.post<ScanJob>(`/api/projects/${enc(projectId)}/scans`, body),
    onSuccess: invalidate,
  });
}

/** Polls every 1.5 s while the job is not in a terminal state. */
export function useScanDetail(projectId: string, scanId: string) {
  return useQuery({
    queryKey: ["scan", projectId, scanId],
    queryFn: () => api.get<ScanDetail>(`/api/projects/${enc(projectId)}/scans/${enc(scanId)}`),
    refetchInterval: (q) => (q.state.data && q.state.data.terminal ? false : 1500),
  });
}

export function useScanEvents(projectId: string, scanId: string, live: boolean) {
  return useQuery({
    queryKey: ["scan-events", projectId, scanId],
    queryFn: () => api.get<EventPage>(`/api/projects/${enc(projectId)}/scans/${enc(scanId)}/events`, { limit: 200 }),
    refetchInterval: live ? 1500 : false,
  });
}

export function useScanConsole(projectId: string, scanId: string, live: boolean) {
  return useQuery({
    queryKey: ["scan-console", projectId, scanId],
    queryFn: () => api.get<{ lines: string[] }>(`/api/projects/${enc(projectId)}/scans/${enc(scanId)}/console`, { lines: 300 }),
    refetchInterval: live ? 1500 : false,
  });
}

export function useCancelScan(projectId: string, scanId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: () => api.post<ScanJob>(`/api/projects/${enc(projectId)}/scans/${enc(scanId)}/cancel`),
    onSuccess: invalidate,
  });
}

export function useRetryScan(projectId: string, scanId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: () => api.post<ScanJob>(`/api/projects/${enc(projectId)}/scans/${enc(scanId)}/retry`, { confirmed: true }),
    onSuccess: invalidate,
  });
}

// ---------------------------------------------------------------- web scanner (Phase 05)

/** Live preview of the web scan profile for the start dialog (read-only). */
export function useWebScanProfile(projectId: string, params: ScanParams, enabled: boolean) {
  return useQuery({
    queryKey: ["web-profile", projectId, params],
    queryFn: () => api.get<WebProfilePreview>(`/api/projects/${enc(projectId)}/web-scan-profile`, params as Record<string, string | number | undefined>),
    enabled,
  });
}

/** Web scanner outputs (summary / coverage / pages); available once the job wrote them. */
export function useScanResult<T>(projectId: string, scanId: string, kind: "summary" | "coverage" | "pages" | "changes", enabled: boolean) {
  return useQuery({
    queryKey: ["scan-result", projectId, scanId, kind],
    queryFn: () => api.get<T>(`/api/projects/${enc(projectId)}/scans/${enc(scanId)}/results/${kind}`),
    enabled,
    retry: false,
  });
}

// ---------------------------------------------------------------- attack surface (Phase 06)

export function useSurfaceProfile(projectId: string, params: Record<string, string | number | boolean | string[] | undefined>, enabled: boolean) {
  return useQuery({
    queryKey: ["surface-profile", projectId, params],
    queryFn: () => api.get<SurfaceProfilePreview>(`/api/projects/${enc(projectId)}/surface-scan-profile`, params),
    enabled,
  });
}

export function useSurface(projectId: string, query: Record<string, string | string[] | undefined>) {
  return useQuery({
    queryKey: ["surface", projectId, query],
    queryFn: () => api.get<SurfaceView>(`/api/projects/${enc(projectId)}/surface`, query),
  });
}

export function useSetCriticality(projectId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: ({ assetId, expectedRevision, criticality }: { assetId: string; expectedRevision: number; criticality: string | null }) =>
      request("PATCH", `/api/projects/${enc(projectId)}/assets/${enc(assetId)}`, { body: { expected_revision: expectedRevision, criticality } }),
    onSuccess: invalidate,
  });
}

export function useApproveAsset(projectId: string) {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: ({ assetId, expectedProjectRevision }: { assetId: string; expectedProjectRevision: number }) =>
      api.post(`/api/projects/${enc(projectId)}/assets/${enc(assetId)}/approve`, { expected_project_revision: expectedProjectRevision, confirmed: true }),
    onSuccess: invalidate,
  });
}
