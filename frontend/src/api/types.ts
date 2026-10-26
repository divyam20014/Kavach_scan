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
export type ScanModule = "web_app" | "attack_surface" | "api_security" | "repo_scan" | "self_test";
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
  { value: "repo_scan", label: "Repository scanner (Semgrep / Gitleaks / Trivy)" },
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
  repository_path: string;
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
  repository_path: string;
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
  trend: ModuleTrend[];
}

export interface ModuleTrend {
  module: string;
  older_scan_id: string;
  newer_scan_id: string;
  older_at: string;
  newer_at: string;
  older_total: number;
  newer_total: number;
  findings_delta: number;
  by_severity_delta: Record<Severity, number>;
}

export interface FindingSource {
  tool: string;
  tool_version: string;
  rule_id: string;
  source_finding_id: string;
  original_severity: string;
  original_confidence: string;
  import_id: string | null;
  scan_id: string | null;
  observed_at: string;
}

export interface DedupEvent {
  action: "merged" | "unmerged" | "reobserved";
  other_finding_id: string | null;
  at: string;
  note: string;
}

export interface FindingComment {
  comment_id: string;
  author: string;
  text: string;
  created_at: string;
}

export interface StandardMapping {
  catalog: "owasp_top10" | "owasp_api_top10" | "cwe";
  catalog_version: string;
  entry_id: string;
  title: string;
  rationale: string;
  confidence: Confidence;
}

export interface CvssRecord {
  version: "3.1" | "4.0";
  vector: string;
  base_score: number;
  source: "supplied" | "calculated";
  calculator: string;
}

export type BusinessPriority = "p1" | "p2" | "p3" | "p4";

export interface Finding {
  schema_version: number;
  finding_id: string;
  project_id: string;
  revision: number;
  created_at: string;
  updated_at: string;
  scan_id?: string | null;
  fingerprint?: string | null;
  rule_id?: string;
  category?: string;
  parameter?: string;
  component?: string;
  title: string;
  summary: string;
  technical_detail: string;
  affected_asset_ids: string[];
  method?: string | null;
  severity: Severity;
  confidence: Confidence;
  verification_state: "unverified" | "automated_evidence" | "manually_verified";
  analyst_status: AnalystStatus;
  business_impact: string;
  business_priority: BusinessPriority | null;
  evidence_ids: string[];
  cwe_ids: number[];
  mappings: StandardMapping[];
  cvss: CvssRecord | null;
  remediation: string;
  references: string[];
  sources: FindingSource[];
  dedup_history: DedupEvent[];
  comments: FindingComment[];
  merged_into: string | null;
  url: string | null;
}

export interface FindingListItem {
  finding: Finding;
  module: string;
  risk_score: number;
  risk_tier: string;
  asset_criticality: string | null;
  reviewed: boolean;
}

export interface FindingDetailView {
  finding: Finding;
  module: string;
  risk: {
    severity_points: number;
    confidence_multiplier: number;
    severity_after_confidence: number;
    asset_criticality_bonus: number;
    exposure_bonus: number;
    verification_bonus: number;
    raw_score: number;
    score: number;
    tier: string;
    capped_for_needs_review: boolean;
  };
  assets: Asset[];
  duplicate_of: Finding | null;
  merged_duplicates: Finding[];
}

export interface CatalogView {
  catalog: string;
  version: string;
  label: string;
  source: string;
  imported_at: string;
  entry_count: number;
  coverage_note: string;
}

export interface RiskFormula {
  formula: string;
  severity_points: Record<Severity, number>;
  confidence_multiplier: Record<Confidence, number>;
  asset_criticality_bonus: Record<string, number>;
  exposure_bonus: { has_url: number; no_url: number };
  verification_bonus: Record<string, number>;
  tier_bands: Record<string, number>;
  needs_review_tier_ceiling: string;
  notes: string;
}

export interface Asset {
  asset_id: string;
  project_id: string;
  asset_type: AssetType;
  locator: string;
  parent_asset_id?: string | null;
  related_asset_ids?: string[];
  scope_status: string;
  confidence: Confidence;
  last_seen: string;
  first_seen?: string;
  revision?: number;
  attributes?: Record<string, string | number | boolean | null>;
  resolution_status?: string | null;
  criticality?: "low" | "medium" | "high" | "critical" | null;
  observations?: string[];
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
  parameters: ScanParams;
  progress: { stage: string; percent: number | null; counters: Record<string, number> };
  cancel_requested: boolean;
  warnings: string[];
  errors: string[];
  output_refs: string[];
  correlation_id: string | null;
  retry_of: string | null;
  final_reason: string;
  scope_hash: string | null;
  tool_versions?: Record<string, string>;
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
  parameters?: ScanParams;
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

// ---------------------------------------------------------------- web scanner (Phase 05)

export type ScanParams = Record<string, string | number | boolean | null | string[]>;

export interface ProfileCheck {
  group: string;
  label: string;
  kind: "passive" | "probe" | "active" | "tool";
  rule_ids: string[];
  enabled: boolean;
  reason: string;
}

export interface WebScanProfile {
  profile_version: number;
  catalog_version: string;
  safe_mode: boolean;
  engine: "native" | "zap";
  auth_profile: string | null;
  respect_robots: boolean;
  tls_verify: boolean;
  seed_paths: string[];
  budgets: {
    max_pages: number;
    max_depth: number;
    requests_per_second: number;
    max_concurrency: number;
    max_requests_per_target: number;
    max_duration_seconds: number;
    max_response_bytes: number;
    max_redirects: number;
  };
  checks: ProfileCheck[];
  limitations: string[];
  zap_spider_max_minutes: number;
  zap_wait_max_minutes: number;
}

export interface WebProfilePreview {
  profile: WebScanProfile;
  problems: string[];
  tls_tools: string[];
  parameters: ScanParams;
}

export interface ComponentInfo {
  name: string;
  version: string;
  confidence: string;
  sources: string[];
  evidence: string[];
}

export interface WebScanSummary {
  schema_version: number;
  catalog_version: string;
  safe_mode: boolean;
  stopped_early: string;
  targets: string[];
  pages_fetched: number;
  endpoints_discovered: number;
  forms_discovered: number;
  parameters_discovered: number;
  requests_sent: number;
  request_errors: number;
  request_retries: number;
  rate_limited_responses: number;
  scope_blocked: number;
  redirects_blocked: number;
  out_of_scope_links: number;
  out_of_scope_hosts: Record<string, number>;
  crawl_skipped: Record<string, number>;
  crawl_limit: string;
  robots: Record<string, string>;
  check_outcomes: { outcome: CheckOutcome; count: number }[];
  findings_created: number;
  findings_reobserved: number;
  findings_by_severity: Record<string, number>;
  tool_versions: Record<string, string>;
  components: ComponentInfo[];
  warnings: string[];
  limitations: string[];
}

/** engine=zap only (roadmap Phase 1): a distinct shape from `WebScanSummary` above, since
 * a ZAP Baseline/Passive run has no crawl/coverage/component data of its own. */
export interface ZapScanSummary {
  engine: "zap";
  zap_version: string;
  targets: string[];
  alerts_found: number;
  findings_created: number;
  findings_reobserved: number;
  limitations: string[];
}

export interface RepoScanEngineResult {
  status: "completed" | "failed";
  findings?: number;
  error?: string;
  errors?: string[];
}

export interface RepoScanSummary {
  engines: Record<string, RepoScanEngineResult>;
  findings_created: number;
  findings_reobserved: number;
  limitations: string[];
}

export type CheckOutcome = "pass" | "observation" | "finding" | "skipped" | "error";

export interface CoverageRow {
  rule_id: string;
  title: string;
  kind: string;
  outcome: CheckOutcome;
  subject: string;
  rationale: string;
  parameter: string;
  severity: Severity | null;
  finding_id: string | null;
}

export interface PageRecord {
  url: string;
  depth: number;
  status: number | null;
  content_type: string;
  title: string;
  bytes: number;
  truncated: boolean;
  final_url: string;
  redirect_chain: string[];
  redirect_blocked_to: string;
  parameters: string[];
  links_found: number;
  forms: number;
  error: string;
  source: string;
}

export interface FormRecord {
  page: string;
  action: string;
  method: string;
  fields: string[];
  login_form: boolean;
}

export interface PagesInventory {
  pages: PageRecord[];
  forms: FormRecord[];
  parameters: string[];
  resources: string[];
}

// ---------------------------------------------------------------- attack surface (Phase 06)

export interface SourcePlan { name: string; label: string; enabled: boolean; disclosure: string }

export interface SurfaceScanProfile {
  profile_version: number;
  roots: string[];
  manual_hosts: number;
  port_method: "auto" | "connect" | "nmap";
  ports: { requested: number[]; tested: number[]; not_tested: Record<string, string> };
  max_hosts: number;
  probe_web: boolean;
  web_max_pages: number;
  read_banners: boolean;
  tls_verify: boolean;
  sources: SourcePlan[];
  dns: string;
  limitations: string[];
}

export interface SurfaceProfilePreview {
  profile: SurfaceScanProfile;
  problems: string[];
  target_problems: string[];
  nmap: string | null;
}

export interface SurfaceAsset {
  asset: Asset;
  candidate_status: string;
  priority: number;
  priority_factors: string[];
  findings: number;
}

export interface SurfaceView {
  items: SurfaceAsset[];
  total: number;
  counts: { type: Record<string, number>; status: Record<string, number> };
  edges: [string, string][];
  truncated: boolean;
}

export interface SurfaceSummary {
  schema_version: number;
  catalog_version: string;
  stopped_early: string;
  roots: string[];
  candidates: number;
  candidates_by_status: Record<string, number>;
  rejected_inputs: string[];
  sources: { name: string; label: string; candidates: number; disclosure: string; sent?: string; error?: string }[];
  passive_sources_enabled: boolean;
  dns: { resolved: number; unresolved: number; not_attempted: number; blocked_addresses: number; method: string };
  port_method: string;
  ports_requested: number[];
  ports_tested: number[];
  ports_not_tested: Record<string, string>;
  hosts_checked: Record<string, { ips: string[]; ports_tested: number[]; method: string; open: number[] }>;
  hosts_not_checked: Record<string, string>;
  open_services: { host: string; ip: string; port: number; service: string; product: string; version: string; banner: string }[];
  web_origins: { origin: string; status: number | null; title: string; server: string; error: string; tls: Record<string, unknown> }[];
  check_outcomes: { outcome: CheckOutcome; count: number }[];
  findings_created: number;
  findings_reobserved: number;
  assets_created: number;
  assets_updated: number;
  tool_versions: Record<string, string>;
  components: ComponentInfo[];
  changes: Record<string, number | boolean | string | null>;
  warnings: string[];
  limitations: string[];
}

export interface SurfaceChanges {
  baseline: boolean;
  previous_scan_id: string | null;
  new_hosts: string[];
  not_observed_hosts: string[];
  status_changes: { host: string; from: string; to: string }[];
  ip_changes: { host: string; from: string[]; to: string[] }[];
  opened_ports: { host: string; port: number }[];
  closed_ports: { host: string; port: number }[];
  new_origins: string[];
  not_observed_origins: string[];
}

// ---------------------------------------------------------------- API security (Phase 07)

export interface ApiParamInfo { name: string; location: string; required: boolean; type: string }
export interface ApiOperation {
  op_id: string; method: string; path: string; key: string; summary: string; tags: string[];
  deprecated: boolean; auth_schemes: string[]; security_required: boolean; parameters: ApiParamInfo[];
  request_content_types: string[]; request_schema_props: string[]; request_required_props: string[];
  response_codes: string[]; response_content_types: string[]; mutating: boolean;
}
export interface ApiServerView { raw: string; expanded: string; in_scope: boolean; reason: string }
export interface ApiSpecSummary {
  import_id: string; display_filename: string; sha256: string; size_bytes: number; status: string;
  uploaded_at: string; kind: string; version: string; title: string; operation_count: number; warnings: string[];
}
export interface ApiSpecDetail {
  summary: ApiSpecSummary;
  inventory: {
    kind: string; version: string; title: string; servers: { raw: string; expanded: string }[];
    operations: ApiOperation[]; security_schemes: Record<string, string>; warnings: string[];
    remote_refs: string[]; cyclic_refs: string[]; global_security: boolean; operation_count: number;
  };
  servers: ApiServerView[];
}
export interface ApiScanPlan {
  problems: string[]; inventory_only: boolean; server_in_scope: boolean; server_reason: string; operations_total: number;
}
// ---------------------------------------------------------------- Import Center (Phase 08)
export interface ImportSummary {
  import_id: string; revision: number; display_filename: string; sha256: string; size_bytes: number;
  source_type: string; source_tool_version: string; status: string; uploaded_at: string;
  parser_version: string; warnings: string[]; record_count: number; mapped_count: number;
  rejected_count: number;
}
export interface ImportPreviewRecord {
  index: number; title: string; severity: string; confidence: string; host: string | null;
  url: string | null; rule_id: string; action: "new" | "update_existing" | "duplicate_in_import";
  existing_finding_id: string | null; duplicate_of_index: number | null;
}
export interface ImportDuplicateCandidate {
  title: string; index_a: number; index_b: number | null; existing_finding_id: string | null;
}
export interface ImportPreview {
  source_type: string; label: string; parser_version: string; source_tool_version: string;
  parsed_count: number; rejected_count: number; warnings: string[];
  records: ImportPreviewRecord[]; duplicate_candidates: ImportDuplicateCandidate[];
  mapping_gaps: string[]; asset_count: number; truncated_sample: boolean;
}
export interface ImportDetail {
  summary: ImportSummary; preview: ImportPreview | null; error: string;
}
export interface ImportCommitResponse {
  import_id: string; findings_created: number; findings_reobserved: number;
  assets_created: number; assets_updated: number;
}
export interface ImportFormats {
  supported: { source_type: string; label: string }[];
  unsupported: { source_type: string; reason: string }[];
}

export interface ApiSummary {
  schema_version: number; catalog_version: string; stopped_early: string; import_id: string;
  spec: string; spec_kind: string; spec_version: string; server: string; inventory_only: boolean;
  operations_total: number; operations_tested: string[]; operations_skipped: Record<string, string>;
  requests_sent: number; auth_aliases_used: string[]; idor_enabled: boolean; mass_write_enabled: boolean;
  rate_probe_enabled: boolean; check_outcomes: { outcome: CheckOutcome; count: number }[];
  findings_created: number; findings_reobserved: number; warnings: string[]; remote_refs: string[]; limitations: string[];
}

// ---------------------------------------------------------------- Reports & backup (Phase 10)

export type ReportFormat = "html" | "pdf" | "json" | "csv";

export interface ReportFilterRequest {
  title?: string;
  classification_label?: string;
  scan_date_from?: string | null;
  scan_date_to?: string | null;
  modules?: string[] | null;
  severity_threshold?: Severity;
  analyst_statuses?: AnalystStatus[] | null;
  finding_ids?: string[] | null;
  include_asset_inventory?: boolean;
  include_evidence?: boolean;
}

export interface ReportPreviewResponse {
  finding_ids: string[];
  asset_ids: string[];
  scan_ids: string[];
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  module_counts: Record<string, number>;
  limitations: string[];
  tool_versions: Record<string, string>;
}

export interface ReportSummary {
  report_id: string;
  project_id: string;
  title: string;
  classification_label: string;
  formats: ReportFormat[];
  finding_count: number;
  asset_count: number;
  evidence_included: boolean;
  created_at: string;
}

export interface BackupPreviewResponse {
  project_id: string;
  project_name: string;
  exported_at: string;
  app_version: string;
  storage_version: number;
  include_evidence_blobs: boolean;
  counts: Record<string, number>;
  checksum_mismatches: string[];
  project_already_exists: boolean;
  warnings: string[];
}

export interface RestoreResponse {
  project_id: string;
  counts: Record<string, number>;
}

// ---------------------------------------------------------------- Settings & integrations (Phase 11)

export interface IntegrationsSettings {
  nmap_path: string;
  sslyze_path: string;
  testssl_path: string;
  zap_path: string;
  semgrep_path: string;
  gitleaks_path: string;
  trivy_path: string;
  docker_path: string;
  online_lookup_credential_alias: string;
}

export interface AppSettings {
  schema_version: number;
  product_name: string;
  disk_space_warning_bytes: number;
  evidence_quota_bytes: number | null;
  report_timezone_label: string;
  integrations: IntegrationsSettings;
  revision: number;
  updated_at: string;
}

export interface IntegrationsSettingsUpdate {
  nmap_path?: string;
  sslyze_path?: string;
  testssl_path?: string;
  zap_path?: string;
  semgrep_path?: string;
  gitleaks_path?: string;
  trivy_path?: string;
  docker_path?: string;
  online_lookup_credential_alias?: string;
}

export interface SettingsUpdateRequest {
  product_name?: string;
  integrations?: IntegrationsSettingsUpdate;
  expected_revision?: number;
}

export type IntegrationStatusValue = "not_configured" | "not_found" | "detected" | "verified" | "error";

export interface ToolUsage {
  project_id: string;
  scan_id: string;
  at: string;
  version: string;
}

export interface IntegrationStatus {
  id: string;
  label: string;
  capability: string;
  configured_path: string;
  detected_path: string;
  status: IntegrationStatusValue;
  version: string;
  last_used: ToolUsage | null;
  last_error: string;
  troubleshooting: string;
}

export interface CveCatalogMetadata {
  source: string;
  catalog_version: string;
  imported_at: string;
  file_sha256: string;
  file_name: string;
  parser_version: string;
  entry_count: number;
  stale_after_days: number;
  is_stale: boolean;
  warnings: string[];
}

export interface TrivyDbStatus {
  downloaded_at: string;
  trivy_version: string;
  size_bytes: number;
}

export interface DockerImageStatus {
  image: string;
  digest: string;
  size_bytes: number;
  verified_version: string;
  pulled_at: string;
}
