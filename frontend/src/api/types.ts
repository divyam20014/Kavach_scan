// Types mirroring the backend Pydantic contracts (backend/app/models, app/services).
// Keep in sync by hand; the backend's OpenAPI document at /openapi.json is the reference.

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "confirmed" | "probable" | "potential" | "needs_review";
export type AnalystStatus =
  | "new"
  | "confirmed"
  | "false_positive"
  | "accepted_risk"
  | "fixed"
  | "retest_needed"
  | "needs_review";
export type ScanState =
  | "queued"
  | "validating"
  | "running"
  | "completed"
  | "completed_with_warnings"
  | "failed"
  | "cancelled"
  | "interrupted"
  | "blocked_scope"
  | "expired_authorization";
export type ScanModule = "web_app" | "attack_surface" | "api_security" | "self_test";
export type ProjectStatus = "active" | "archived";
export type AuthorizationStatus = "missing" | "not_started" | "active" | "expiring_soon" | "expired";
export type AssetType = "domain" | "hostname" | "ip" | "port" | "service" | "url" | "api_operation";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
export const CONFIDENCES: Confidence[] = ["confirmed", "probable", "potential", "needs_review"];
export const ANALYST_STATUSES: AnalystStatus[] = [
  "new",
  "confirmed",
  "false_positive",
  "accepted_risk",
  "fixed",
  "retest_needed",
  "needs_review",
];
export const SCAN_MODULES: { value: ScanModule; label: string }[] = [
  { value: "web_app", label: "Web application scanner (Option A)" },
  { value: "attack_surface", label: "Attack surface mapper (Option B)" },
  { value: "api_security", label: "API security testing (Option C)" },
];

export interface RecordError {
  record_id: string | null;
  project_id: string | null;
  kind: string;
  message: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  errors: RecordError[];
}

export interface AuthorizationRecord {
  organization: string;
  target_owner: string;
  authorized_by: string;
  reference: string;
  window_start: string;
  window_end: string;
  attestation_event_id: string | null;
  notes: string;
}

export interface ScopeExclusions {
  hosts: string[];
  wildcard_domains: string[];
  ip_ranges: string[];
  ports: number[];
  path_prefixes: string[];
}

export interface ScopeDefinition {
  schemes: ("http" | "https")[];
  hosts: string[];
  wildcard_domains: string[];
  ip_ranges: string[];
  ports: number[];
  path_prefixes: string[];
  api_server_urls: string[];
  exclusions: ScopeExclusions;
  redirect_policy: "same_scope_only";
  internal_override: unknown | null;
}

export interface ActiveProbeToggles {
  sqli_error_differential: boolean;
  xss_reflection: boolean;
  api_mutating_operations: boolean;
  api_idor: boolean;
  api_rate_limit_probe: boolean;
}

export interface ScanPolicy {
  max_concurrency: number;
  requests_per_second: number;
  connect_timeout_seconds: number;
  read_timeout_seconds: number;
  max_redirects: number;
  max_crawl_depth: number;
  max_pages: number;
  max_response_bytes: number;
  max_duration_seconds: number;
  max_requests_per_target: number;
  allowed_modules: ScanModule[];
  active_probes: ActiveProbeToggles;
  evidence_retention_days: number | null;
}

export interface Project {
  schema_version: 1;
  project_id: string;
  revision: number;
  created_at: string;
  updated_at: string;
  name: string;
  client_name: string;
  description: string;
  status: ProjectStatus;
  authorization: AuthorizationRecord | null;
  scope: ScopeDefinition;
  scan_policy: ScanPolicy;
  labels: string[];
  notes: string;
}

export interface LastScan {
  scan_id: string;
  state: ScanState;
  at: string | null;
}

export interface ProjectOverview {
  project: Project;
  authorization_status: AuthorizationStatus;
  authorization_expires_at: string | null;
  last_scan: LastScan | null;
  counts: Record<"scan" | "finding" | "asset" | "evidence" | "import" | "report", number>;
}

export interface AuthorizationInput {
  organization: string;
  target_owner: string;
  authorized_by: string;
  reference: string;
  window_start: string;
  window_end: string;
  notes: string;
  attestation: boolean;
}

export interface ProjectCreate {
  name: string;
  client_name: string;
  description: string;
  labels: string[];
  notes: string;
  authorization: AuthorizationInput | null;
  scope: ScopeDefinition;
  scope_preview_hash: string | null;
  scan_policy: Partial<ScanPolicy>;
}

export type ProjectUpdate = Partial<Omit<ProjectCreate, "authorization">> & {
  expected_revision: number;
  status?: ProjectStatus;
  authorization?: AuthorizationInput;
};

export interface DeletionImpact {
  project_id: string;
  name: string;
  counts: Record<string, number>;
  confirm_with: string;
}

export interface ScopePreviewRequest {
  targets: string[];
  schemes: ("http" | "https")[];
  ports: string[];
  path_prefixes: string[];
  exclude_targets: string[];
  exclude_ports: string[];
  exclude_paths: string[];
  api_server_urls: string[];
}

export interface PreviewEntry {
  field: string;
  input: string;
  kind: string;
  normalized: string | null;
  error: string | null;
  warnings: string[];
}

export interface BlockedRange {
  network: string;
  category: string;
  label: string;
  overridable: boolean;
}

export interface ScopePreviewResponse {
  valid: boolean;
  scope: ScopeDefinition | null;
  scope_hash: string | null;
  entries: PreviewEntry[];
  error_count: number;
  notes: string[];
  blocked_ranges: BlockedRange[];
}

export interface Decision {
  decision_id: string;
  at: string;
  allowed: boolean;
  reason: string;
  message: string;
  check: string;
  input: string;
  target: string | null;
  ip: string | null;
  rule: string | null;
  project_id: string | null;
  scope_hash: string | null;
}

export interface InternalTargetOverride {
  ip_ranges: string[];
  reason: string;
  expires_at: string;
  audit_event_id: string;
}

export interface ScopePolicyView {
  project_id: string;
  scope: ScopeDefinition;
  scope_hash: string;
  valid: boolean;
  authorization: Decision;
  can_start_active_work: boolean;
  internal_override: { override: InternalTargetOverride; active: boolean } | null;
  warnings: string[];
  blocked_ranges: BlockedRange[];
}

export interface ScopeCheckResponse {
  allowed: boolean;
  summary: string;
  authorization: Decision;
  target: Decision;
  resolved_ips: Decision[];
  dns_note: string | null;
}

export interface InternalOverrideRequest {
  expected_revision: number;
  ip_ranges: string[];
  reason: string;
  expires_at: string;
  attestation: boolean;
}

export interface AuditEvent {
  event_id: string;
  ts: string;
  actor: string;
  project_id: string | null;
  action: string;
  target_ids: string[];
  outcome: "success" | "failure" | "blocked" | "denied";
  metadata: Record<string, unknown>;
  correlation_id: string | null;
}

export interface AuditPage {
  items: AuditEvent[];
  offset: number;
  limit: number;
  has_more: boolean;
  corrupt_lines: number;
}

export interface DashboardSummary {
  generated_at: string;
  project_id: string | null;
  projects: { total: number; active: number; archived: number; authorization: Record<AuthorizationStatus, number> };
  scans: {
    total: number;
    active: number;
    failed: number;
    by_state: Record<ScanState, number>;
    last_scan_at: string | null;
    last_scan_state: ScanState | null;
  };
  findings: {
    total: number;
    open: number;
    by_severity: Record<Severity, number>;
    by_status: Record<AnalystStatus, number>;
    by_confidence: Record<Confidence, number>;
  };
  assets: { total: number; by_type: Record<AssetType, number> };
  recent_activity: AuditEvent[];
  unreadable_records: number;
}

export interface Finding {
  finding_id: string;
  project_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  analyst_status: AnalystStatus;
  url: string | null;
  updated_at: string;
}

export interface Asset {
  asset_id: string;
  project_id: string;
  asset_type: AssetType;
  locator: string;
  scope_status: string;
  confidence: Confidence;
  last_seen: string;
}

export interface ScanJob {
  scan_id: string;
  project_id: string;
  module: ScanModule;
  profile: string;
  state: ScanState;
  revision: number;
  created_at: string;
  updated_at: string;
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  targets: string[];
  authorized_targets: string[];
  parameters: Record<string, string | number | boolean | null>;
  progress: { stage: string; percent: number | null; counters: Record<string, number> };
  cancel_requested: boolean;
  warnings: string[];
  errors: string[];
  output_refs: string[];
  correlation_id: string | null;
  retry_of: string | null;
  final_reason: string;
  scope_hash: string | null;
}

export interface ScanDetail {
  scan: ScanJob;
  active: boolean;
  terminal: boolean;
  elapsed_seconds: number | null;
}

export interface JobEvent {
  event_id: string;
  ts: string;
  scan_id: string;
  type: string;
  level: "debug" | "info" | "warning" | "error";
  stage: string;
  message: string;
  data: Record<string, unknown>;
  correlation_id: string | null;
}

export interface EventPage {
  items: JobEvent[];
  offset: number;
  limit: number;
  has_more: boolean;
  corrupt_lines: number;
}

export interface ModuleAvailability {
  module: ScanModule;
  label: string;
  available: boolean;
  reason: string;
}

export interface ManagerStatus {
  running: boolean;
  active_jobs: string[];
  queued_jobs: number;
  max_active_jobs: number;
  max_queued_jobs: number;
  kill_switch_engaged: boolean;
}

export interface KillSwitchState {
  engaged: boolean;
  changed_at: string | null;
  reason: string;
  actor: string;
}

export interface StartScanRequest {
  module: ScanModule;
  targets: string[];
  profile?: string;
  parameters?: Record<string, string | number | boolean | null>;
  idempotency_key?: string;
  confirmed: boolean;
}

export interface VersionInfo {
  name: string;
  version: string;
  api_version: string;
  storage_version: number;
  python: string;
  scanning_available: boolean;
}

export interface StorageDiagnostics {
  storage: {
    data_dir: string;
    exists: boolean;
    initialized: boolean;
    writable: boolean;
    storage_version: number | null;
    supported_storage_version: number;
    instance_lock: string;
    free_bytes: number | null;
    total_bytes: number | null;
    low_disk_space: boolean;
    warnings: string[];
    ready: boolean;
    checked_at: string;
  };
  last_integrity_check: { checked_at: string; issues: { kind: string; message: string; location: string }[] } | null;
}

export interface ErrorDetail {
  loc: (string | number)[];
  message: string;
  type: string | null;
}
