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
  /** Feature 0091: the target this scan belongs to (lineage grouping key). */
  target_key?: string;
  status: AuditStatus;
  types: string[];
  config?: Record<string, unknown>;
  findings?: Finding[];
  findings_count?: number;
  scores?: Record<string, number>;
  prove_results?: ProveResult[];
  prove_count?: number;
  /** Feature 0063: persisted OWASP Top 10 coverage manifest, so it survives
   * reload / viewing a completed audit (the live stream is not the only view). */
  owasp_coverage?: OwaspCoverageManifest;
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
  /** Path-canonical identity; the lineage writer matches on it before `fingerprint`. */
  fingerprint_v2?: string;
  cross_agent_origins?: string[];
  // Feature 0058 (R6) — detection tier that produced the finding
  // (e.g. "skill", "signature", "semgrep"). Optional because pre-0058
  // findings won't carry it.
  provenance?: string;
  // Feature 0045/0046 — validation layer outputs persisted on the
  // finding record. Optional because pre-0045 audits won't have them.
  validation_status?: string;
  validation_confidence?: number;
  validation?: Record<string, unknown>;
  /** Feature 0096: framework categories applied from a mapping agent's table. Absent when none. */
  compliance_labels?: ComplianceLabel[];
}

/**
 * Feature 0096: one (framework, edition, category) label on a finding. It
 * replaces the OWASP copy row: the finding is counted and triaged once, and
 * `cwe` names the category the label was derived from.
 */
export interface ComplianceLabel {
  framework: string;
  edition: string;
  category_id: string;
  category_name: string;
  cwe: string;
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

// Feature 0063: OWASP Top 10 coverage manifest emitted on the OWASP agent's
// result event (owasp_coverage). The OWASP agent maps CWE findings onto
// OWASP categories; this reports per-category coverage for the edition.
export interface OwaspCategoryCoverage {
  id: string;
  name: string;
  mapped_count: number;
  found_cwes: string[];
  found_count: number;
  status: "found" | "clean-or-undetected";
  source_url: string;
  /**
   * Feature 0096: `false` on a category outside the audit's `categories`
   * subset — the backend found nothing there by choice. Absent otherwise
   * (including every manifest the agent streams live).
   */
  selected?: boolean;
  /**
   * Feature 0096 follow-up: how many distinct findings carrying a label of
   * this category are triaged false positive (their own lineage row). The
   * backend leaves those findings out of found_cwes / found_count when the
   * audit is read. Present on mapping-mode manifests served by the backend;
   * absent on a streamed or pre-0096 manifest.
   */
  false_positive_count?: number;
}

export interface OwaspCoverageManifest {
  edition: string;
  cwe_stage_status: "completed" | "partial" | "failed" | "absent";
  categories: OwaspCategoryCoverage[];
}

export type LineageStatus =
  | "open"
  | "in_progress"
  | "unconfirmed"
  | "resolved"
  | "accepted_risk"
  | "false_positive"
  | "fixed"
  | "regression";

/**
 * Feature 0091: the lineage event vocabulary. The first five predate 0091; the
 * rest are the evidence-check and scope outcomes recorded by the P0-P3 scan
 * pass. Kept as a union so a component that switches on the type cannot
 * silently forget one, but every consumer also has a generic fallback because
 * a future backend may emit an event this build has never heard of.
 */
export type LineageEventType =
  | "detected"
  | "status_change"
  | "fixed"
  | "regression"
  | "note_added"
  | "confirmed_by_evidence"
  | "evidence_gone"
  | "unconfirmable"
  | "out_of_scope"
  | "scope_unknown"
  | "absent_in_result"
  | "skipped_degraded"
  | "memory_synced"
  | "merged";

/** Detection tier of a lineage row: deterministic skill, or LLM. */
export type FindingTier = "det" | "llm";

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
  // --- feature 0091 ---
  /** Stable identity of the codebase the finding belongs to. */
  target_key?: string;
  /** Path-independent fingerprint; `seen_in` is computed from it. */
  fingerprint_v2?: string;
  git_branch?: string;
  seen_count?: number;
  last_seen_audit_id?: string;
  /** Result of the last evidence re-read of the cited file. */
  evidence?: LineageEvidence;
  /** Audit ids this finding was reported in, newest first. */
  seen_in?: string[];
  /**
   * Feature 0096: "framework:edition" (e.g. "owasp:2025") -> category ids of
   * that edition's full table. Kept across scans that do not run the edition.
   */
  compliance_labels?: Record<string, string[]>;
}

/**
 * Feature 0091: the outcome of re-reading the cited file for the stored
 * evidence quote. `last_outcome` is what decides whether an LLM-tier row may
 * close; the window and file hash say what was actually read.
 */
export interface LineageEvidence {
  last_outcome: string;
  reason?: string;
  line_start?: number;
  line_end?: number;
  file_hash?: string;
  checked_at?: string;
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
  /**
   * Feature 0096: the previous audit's pre-0096 OWASP copy rows left out of
   * the classification, because this audit labels those findings instead of
   * copying them. Omitted when zero.
   */
  excluded_legacy_copies?: number;
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

// --- Targets and the aggregate report (feature 0091) ---

/** One row of GET /api/targets. */
export interface TargetSummary {
  target_key: string;
  display_name: string;
  scan_count: number;
  active_count: number;
  unconfirmed_count: number;
  fixed_count: number;
  last_scan_at?: string;
  last_audit_id?: string;
}

/** One row of GET /api/targets/{key}/scans, newest first. */
export interface TargetScan {
  audit_id: string;
  created_at: string;
  /** "" for a scan of the target root. */
  sub_path: string;
  git_branch?: string;
  det_count: number;
  llm_count: number;
  types: string[];
}

/**
 * One unique finding of the aggregate report. Computed from `finding_lineage`
 * alone — there is no `Finding` behind it, which is why the fields are named
 * for the lineage row (`rel_path`, `seen_count`) rather than for a finding.
 */
export interface AggregateRow {
  lineage_id: string;
  ref: string;
  severity: Severity;
  category: string;
  title: string;
  rel_path: string;
  line_start?: number;
  tier: FindingTier;
  /** Scans this finding was seen in, out of `scan_count` scans of the target. */
  seen_count: number;
  scan_count: number;
  status: LineageStatus;
  first_seen_at: string;
  last_seen_at: string;
  /** Free-form: a build may not know every event the backend can emit. */
  last_event: string;
  /** Feature 0096: the lineage row's labels, "framework:edition" -> category ids. */
  compliance_labels?: Record<string, string[]>;
}

export interface AggregateTiles {
  unique: number;
  active: number;
  unconfirmed: number;
  fixed: number;
  critical: number;
}

export interface AggregateResponse {
  total: number;
  page: number;
  page_size: number;
  tiles: AggregateTiles;
  rows: AggregateRow[];
  /**
   * Feature 0096: every (framework, edition) the target's lineage rows carry
   * labels for, with the categories under each — what the OWASP filter
   * offers. Covers the selected scans and every status, and is not narrowed
   * by the status/severity/tier/compliance filters; sorted by framework, then
   * newest edition. Absent from an older backend; read as none.
   */
  label_editions?: LabelEdition[];
}

/** One (framework, edition) of `AggregateResponse.label_editions`. */
export interface LabelEdition {
  framework: string;
  edition: string;
  /** The category ids the target's rows carry under this edition, sorted. */
  categories?: string[];
}

/**
 * Query of GET /api/targets/{key}/aggregate. Every field is optional and an
 * omitted field means the server default ("all scans", "both tiers",
 * "active only") — the client never invents a default of its own.
 */
export interface AggregateFilters {
  scans?: string[];
  status?: "active" | "all";
  tier?: FindingTier;
  min_seen?: number;
  severity?: string[];
  /** Feature 0096: rows labelled `category` under `framework` (e.g. owasp / A07). */
  framework?: string;
  category?: string;
  /** Edition of `framework`; required with `category` — a category id means different things per edition. */
  edition?: string;
  page?: number;
  page_size?: number;
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
