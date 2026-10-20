import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type {
  Asset,
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
