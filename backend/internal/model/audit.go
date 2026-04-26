package model

import (
	"encoding/json"
	"time"
)

type AuditStatus string

const (
	AuditStatusPending   AuditStatus = "pending"
	AuditStatusRunning   AuditStatus = "running"
	AuditStatusCompleted AuditStatus = "completed"
	AuditStatusFailed    AuditStatus = "failed"
)

type Audit struct {
	ID             string            `json:"id"`
	SourceID       string            `json:"source_id"`
	SourcePath     string            `json:"source_path,omitempty"`
	Types          []string          `json:"types"`
	Config         json.RawMessage   `json:"config"`
	Status         AuditStatus       `json:"status"`
	Findings       []Finding         `json:"findings,omitempty"`
	FindingsCount  int               `json:"findings_count"`
	Scores         map[string]int    `json:"scores,omitempty"`
	ProveResults   []ProveResult     `json:"prove_results,omitempty"`
	ProveCount     int               `json:"prove_count,omitempty"`
	WebhookURL     string            `json:"webhook_url,omitempty"`
	DegradedReason string            `json:"degraded_reason,omitempty"` // Feature 0039: canonical LLMHealthStatus.message() when LLM unreachable at submit time
	CreatedAt      time.Time         `json:"created_at"`
	CompletedAt    *time.Time        `json:"completed_at,omitempty"`
}

type AuditRequest struct {
	SourceID       string          `json:"source_id"`
	Types          []string        `json:"types"`
	Config         json.RawMessage `json:"config"`
	WebhookURL     string          `json:"webhook_url,omitempty"`     // Feature 0031: optional callback on completion
	DegradedReason string          `json:"degraded_reason,omitempty"` // Feature 0039: populated by handler from /api/llm/health preflight; not user-supplied

}

// AuditComparison holds the diff between the current audit and the previous one.
type AuditComparison struct {
	HasPrevious           bool                       `json:"has_previous"`
	PreviousAuditID       string                     `json:"previous_audit_id,omitempty"`
	PreviousCommit        string                     `json:"previous_commit,omitempty"`
	PreviousBranch        string                     `json:"previous_branch,omitempty"`
	PreviousDate          *time.Time                 `json:"previous_date,omitempty"`
	PreviousFindingsCount int                        `json:"previous_findings_count,omitempty"`
	CurrentFindingsCount  int                        `json:"current_findings_count"`
	NewCount              int                        `json:"new_count"`
	FixedCount            int                        `json:"fixed_count"`
	PersistentCount       int                        `json:"persistent_count"`
	ChangedCount          int                        `json:"changed_count"`
	RegressionCount       int                        `json:"regression_count"`
	NewFindings           []ComparisonFindingSummary  `json:"new_findings,omitempty"`
	FixedFindings         []ComparisonFindingSummary  `json:"fixed_findings,omitempty"`
	ChangedFindings       []ComparisonChangedFinding  `json:"changed_findings,omitempty"`
}

// ComparisonFindingSummary is a lightweight summary for new/fixed findings.
// Ref / RefNumber are populated when the audit handler enriches the response
// with the FindingLineage record matching this fingerprint, so UI consumers
// can display a stable "VLT-XXXX" identifier alongside the finding.
type ComparisonFindingSummary struct {
	Fingerprint string   `json:"fingerprint"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	FilePath    string   `json:"file_path"`
	AgentType   string   `json:"agent_type"`
	Ref         string   `json:"ref,omitempty"`
	RefNumber   int      `json:"ref_number,omitempty"`
}

// ComparisonChangedFinding tracks findings whose severity changed between audits.
type ComparisonChangedFinding struct {
	Fingerprint string   `json:"fingerprint"`
	Title       string   `json:"title"`
	OldSeverity Severity `json:"old_severity"`
	NewSeverity Severity `json:"new_severity"`
	AgentType   string   `json:"agent_type"`
	Ref         string   `json:"ref,omitempty"`
	RefNumber   int      `json:"ref_number,omitempty"`
	FilePath    string   `json:"file_path"`
}
