package model

import "time"

// ProveStatus represents the verification status of a finding.
type ProveStatus string

const (
	ProveStatusVerified      ProveStatus = "verified"
	ProveStatusNotReproduced ProveStatus = "not_reproduced"
	ProveStatusInconclusive  ProveStatus = "inconclusive"
	ProveStatusSkipped       ProveStatus = "skipped"
)

// ProveResult stores the verification outcome for a single finding.
type ProveResult struct {
	ID             string      `json:"id"`
	AuditID        string      `json:"audit_id"`
	FindingID      string      `json:"finding_id"`
	Status         ProveStatus `json:"status"`
	Evidence       string      `json:"evidence"`
	IterationsUsed int         `json:"iterations_used"`
	Fingerprint    string      `json:"fingerprint"`
	StagingURL     string      `json:"staging_url"`
	CreatedAt      time.Time   `json:"created_at"`
}

// ProveSummary is an aggregate view of prove results for an audit.
type ProveSummary struct {
	AuditID       string `json:"audit_id"`
	Total         int    `json:"total"`
	Verified      int    `json:"verified"`
	NotReproduced int    `json:"not_reproduced"`
	Inconclusive  int    `json:"inconclusive"`
	Skipped       int    `json:"skipped"`
}
