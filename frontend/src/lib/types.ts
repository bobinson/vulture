export type AuditStatus = "pending" | "running" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AgentStepStatus = "pending" | "running" | "complete" | "failed";

export interface Source {
  id: string;
  type: "git" | "local";
  url?: string;
  path?: string;
  file_count?: number;
  git_branch?: string;
  git_commit_hash?: string;
  git_commit_short?: string;
  git_remote_url?: string;
  created_at: string;
}

export interface AgentInfo {
  id: string;
  name: string;
  type: string;
  status?: "healthy" | "unhealthy" | "unknown";
  description?: string;
  config_schema?: Record<string, unknown>;
  /**
   * Optional agents are excluded from the default scan set and only
   * run when explicitly selected. The selector visually distinguishes
   * them so users know they aren't in the default flow.
   */
  optional?: boolean;
}

export type ProveStatus = "verified" | "not_reproduced" | "inconclusive" | "skipped";

export interface ProveResult {
  id: string;
  audit_id: string;
  finding_id: string;
  fingerprint?: string;
  status: ProveStatus;
  evidence: string;
  iterations_used: number;
  staging_url: string;
  created_at: string;
}

export interface Audit {
  id: string;
  source_id: string;
  source_path?: string;
  status: AuditStatus;
  types: string[];
  config?: Record<string, unknown>;
  findings?: Finding[];
  findings_count?: number;
  scores?: Record<string, number>;
  prove_results?: ProveResult[];
  prove_count?: number;
  /** Feature 0039: canonical LLMHealthStatus.message() when LLM was unreachable
   * at audit-creation time. Empty/undefined means the audit ran in normal mode. */
  degraded_reason?: string;
  created_at: string;
  completed_at?: string;
}

/** Feature 0039: live LLM health status from /api/llm/health. */
export interface LLMHealth {
  provider: string;
  endpoint: string;
  model: string;
  reachable: boolean;
  error?: string;
  detail?: Record<string, unknown>;
  message: string;
}

export interface Finding {
  id?: string;
  audit_id?: string;
  agent_id?: string;
  agent_type?: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  file_path: string;
  line_start?: number;
  line_end?: number;
  check_id?: string;
  code_snippet?: string;
  recommendation: string;
  compliance_ref?: string;
  fingerprint?: string;
  cross_agent_origins?: string[];
  // Feature 0045/0046 — validation layer outputs persisted on the
  // finding record. Optional because pre-0045 audits won't have them.
  validation_status?: string;
  validation_confidence?: number;
  validation?: Record<string, unknown>;
}

export interface AgentStep {
  agent_id: string;
  label: string;
  status: AgentStepStatus;
  timestamp: string;
}

export interface StreamLine {
  id: string;
  text: string;
  type: "info" | "finding" | "error" | "step" | "progress";
  timestamp: Date;
}

export interface CreateSourceRequest {
  type: "git" | "local";
  url?: string;
  path?: string;
}

export interface CreateAuditRequest {
  source_id: string;
  types: string[];
  config?: Record<string, unknown>;
}

export interface DashboardStats {
  audits_run: number;
  total_findings: number;
  critical_issues: number;
  average_score: number;
  prove_verified: number;
  prove_total: number;
}

export interface CacheCheckResponse {
  cached: boolean;
  audit?: Audit;
}

export interface DirEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size?: number;
}

export interface BrowseResponse {
  path: string;
  parent: string;
  entries: DirEntry[];
}

export interface AuditMemory {
  id: string;
  audit_id: string;
  agent_type: string;
  codebase_path: string;
  finding_type: string;
  title: string;
  content: string;
  severity: Severity;
  category: string;
  keywords: string[];
  tags: string[];
  file_paths: string[];
  remediation_status: string;
  remediation_notes?: string;
  created_at: string;
  similarity?: number;
}

export interface MemoryEdge {
  id: string;
  source_id: string;
  target_id: string;
  relation_type: string;
  strength: number;
  bidirectional: boolean;
  created_by?: string;
  created_at: string;
  target_title?: string;
  target_severity?: string;
}

export interface MemoryWithEdges extends AuditMemory {
  edges?: MemoryEdge[];
}

export interface TokenSavings {
  context_tokens: number;
  raw_tokens: number;
  tokens_saved: number;
  savings_pct: number;
  prior_findings_used: number;
  duplicates_removed: number;
  actual_input_tokens?: number;
  actual_output_tokens?: number;
}

export interface DedupStats {
  findings_deduped: number;
  prior_findings_used: number;
  duplicates_removed: number;
}

export type LineageStatus = "open" | "in_progress" | "resolved" | "accepted_risk" | "false_positive" | "fixed" | "regression";
export type LineageEventType = "detected" | "status_change" | "fixed" | "regression" | "note_added";

export interface FindingLineage {
  id: string;
  fingerprint: string;
  source_path: string;
  agent_type: string;
  current_status: LineageStatus;
  ref_number?: number;
  ref?: string;
  notes?: string;
  ticket_url?: string;
  first_audit_id: string;
  first_found_at: string;
  first_commit?: string;
  latest_audit_id?: string;
  latest_found_at?: string;
  latest_commit?: string;
  fixed_audit_id?: string;
  fixed_at?: string;
  fixed_commit?: string;
  severity: string;
  category: string;
  title: string;
  file_path: string;
  created_at: string;
  updated_at: string;
  events?: LineageEvent[];
}

export interface LineageEvent {
  id: string;
  lineage_id: string;
  event_type: LineageEventType;
  audit_id?: string;
  git_commit?: string;
  git_branch?: string;
  old_status?: string;
  new_status?: string;
  notes?: string;
  created_at: string;
}

export interface LineageStatusUpdate {
  status: string;
  notes?: string;
  ticket_url?: string;
}

export interface AuditComparison {
  has_previous: boolean;
  previous_audit_id?: string;
  previous_commit?: string;
  previous_branch?: string;
  previous_date?: string;
  previous_findings_count?: number;
  current_findings_count: number;
  new_count: number;
  fixed_count: number;
  persistent_count: number;
  changed_count: number;
  regression_count: number;
  new_findings?: ComparisonFindingSummary[];
  fixed_findings?: ComparisonFindingSummary[];
  changed_findings?: ComparisonChangedFinding[];
}

export interface ComparisonFindingSummary {
  fingerprint: string;
  title: string;
  severity: Severity;
  file_path: string;
  agent_type: string;
  ref?: string;          // e.g. "VLT-3890"; populated when lineage record exists
  ref_number?: number;
}

export interface ComparisonChangedFinding {
  fingerprint: string;
  title: string;
  old_severity: Severity;
  new_severity: Severity;
  agent_type: string;
  file_path: string;
  ref?: string;
  ref_number?: number;
}

// --- Pipeline (scan → discover → prove) ---

export type PipelineStatus =
  | "pending"
  | "scan_running"
  | "discover_running"
  | "prove_running"
  | "completed"
  | "failed";

export interface Pipeline {
  id: string;
  target_url: string;
  source_id?: string;
  stages: string[];
  config?: Record<string, unknown>;
  scan_audit_id?: string;
  discover_audit_id?: string;
  prove_audit_id?: string;
  status: PipelineStatus;
  created_at: string;
  completed_at?: string;
}

export interface CreatePipelineRequest {
  source_id?: string;
  target_url: string;
  stages: string[];
  config?: Record<string, unknown>;
}

export interface DiscoverResult {
  id: string;
  audit_id: string;
  target_url: string;
  site_map_json: string;
  url_count: number;
  api_count: number;
  form_count: number;
  technologies: string[];
  created_at: string;
}

/** Validate URL has http/https scheme to prevent javascript: XSS. */
export function safeExternalUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") return url;
    return undefined;
  } catch {
    return undefined;
  }
}
