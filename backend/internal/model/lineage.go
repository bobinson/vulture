package model

import "time"

// LineageStatus represents the lifecycle state of a finding across audits.
type LineageStatus string

const (
	LineageStatusOpen         LineageStatus = "open"
	LineageStatusInProgress   LineageStatus = "in_progress"
	LineageStatusResolved     LineageStatus = "resolved"
	LineageStatusAcceptedRisk LineageStatus = "accepted_risk"
	LineageStatusFalsePositive LineageStatus = "false_positive"
	LineageStatusFixed        LineageStatus = "fixed"
	LineageStatusRegression   LineageStatus = "regression"
)

// LineageEventType describes what happened to a lineage record.
type LineageEventType string

const (
	LineageEventDetected     LineageEventType = "detected"
	LineageEventStatusChange LineageEventType = "status_change"
	LineageEventFixed        LineageEventType = "fixed"
	LineageEventRegression   LineageEventType = "regression"
	LineageEventNoteAdded    LineageEventType = "note_added"
)

// FindingLineage tracks a unique finding across multiple audit runs.
type FindingLineage struct {
	ID            string        `json:"id"`
	Fingerprint   string        `json:"fingerprint"`
	SourcePath    string        `json:"source_path"`
	AgentType     string        `json:"agent_type"`
	CurrentStatus LineageStatus `json:"current_status"`
	Notes         string        `json:"notes,omitempty"`
	TicketURL     string        `json:"ticket_url,omitempty"`
	FirstAuditID  string        `json:"first_audit_id"`
	FirstFoundAt  time.Time     `json:"first_found_at"`
	FirstCommit   string        `json:"first_commit,omitempty"`
	LatestAuditID string        `json:"latest_audit_id,omitempty"`
	LatestFoundAt *time.Time    `json:"latest_found_at,omitempty"`
	LatestCommit  string        `json:"latest_commit,omitempty"`
	FixedAuditID  string        `json:"fixed_audit_id,omitempty"`
	FixedAt       *time.Time    `json:"fixed_at,omitempty"`
	FixedCommit   string        `json:"fixed_commit,omitempty"`
	Severity      string        `json:"severity"`
	Category      string        `json:"category"`
	Title         string        `json:"title"`
	FilePath      string        `json:"file_path"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// LineageEvent is a single audit-trail entry for a lineage record.
type LineageEvent struct {
	ID        string           `json:"id"`
	LineageID string           `json:"lineage_id"`
	EventType LineageEventType `json:"event_type"`
	AuditID   string           `json:"audit_id,omitempty"`
	GitCommit string           `json:"git_commit,omitempty"`
	GitBranch string           `json:"git_branch,omitempty"`
	OldStatus string           `json:"old_status,omitempty"`
	NewStatus string           `json:"new_status,omitempty"`
	Notes     string           `json:"notes,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
}

// LineageStatusUpdate is the request body for PATCH /api/lineage/:id.
type LineageStatusUpdate struct {
	Status    string `json:"status"`
	Notes     string `json:"notes,omitempty"`
	TicketURL string `json:"ticket_url,omitempty"`
}
