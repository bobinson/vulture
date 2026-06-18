package model

import "time"

type AuditMemory struct {
	ID                string    `json:"id"`
	CreatedAt         time.Time `json:"created_at"`
	AuditID           string    `json:"audit_id"`
	AgentType         string    `json:"agent_type"`
	CodebasePath      string    `json:"codebase_path"`
	FindingType       string    `json:"finding_type"`
	Title             string    `json:"title"`
	Content           string    `json:"content"`
	Severity          Severity  `json:"severity"`
	Fingerprint       string    `json:"fingerprint,omitempty"`
	ComplianceRef     string    `json:"compliance_ref,omitempty"`
	Category          string    `json:"category"`
	Keywords          []string  `json:"keywords"`
	Tags              []string  `json:"tags"`
	FilePaths         []string  `json:"file_paths"`
	RemediationStatus string    `json:"remediation_status"`
	RemediationNotes  string    `json:"remediation_notes,omitempty"`
	ConfidenceScore   float64   `json:"confidence_score"`
	CWEName           string    `json:"cwe_name,omitempty"`
	CWELikelihood     string    `json:"cwe_likelihood,omitempty"`
	Similarity        float64   `json:"similarity,omitempty"`
	Embedding         []float32 `json:"-"`
}

type DashboardStats struct {
	AuditsRun      int `json:"audits_run"`
	TotalFindings  int `json:"total_findings"`
	CriticalIssues int `json:"critical_issues"`
	AverageScore   int `json:"average_score"`
	ProveVerified  int `json:"prove_verified"`
	ProveTotal     int `json:"prove_total"`
}

type MemorySearchRequest struct {
	Query     string `json:"query"`
	AuditID   string `json:"audit_id,omitempty"`
	AgentType string `json:"agent_type,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type MemoryEdge struct {
	ID             string    `json:"id"`
	SourceID       string    `json:"source_id"`
	TargetID       string    `json:"target_id"`
	RelationType   string    `json:"relation_type"`
	Strength       float64   `json:"strength"`
	Bidirectional  bool      `json:"bidirectional"`
	CreatedBy      string    `json:"created_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	TargetTitle    string    `json:"target_title,omitempty"`
	TargetSeverity string    `json:"target_severity,omitempty"`
}

// MemoryWithEdges wraps a memory with its connected edges for graph display.
type MemoryWithEdges struct {
	AuditMemory
	Edges []MemoryEdge `json:"edges,omitempty"`
}
