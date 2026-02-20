package model

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID             string   `json:"id"`
	AuditID        string   `json:"audit_id"`
	AgentType      string   `json:"agent_type"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	FilePath       string   `json:"file_path"`
	LineStart      int      `json:"line_start"`
	LineEnd        int      `json:"line_end"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
}

// PriorFinding is a lightweight summary of a previous finding passed to agents
// so they can skip re-analyzing known issues and save LLM tokens.
type PriorFinding struct {
	Title             string `json:"title"`
	Severity          string `json:"severity"`
	Category          string `json:"category"`
	FilePath          string `json:"file_path"`
	RemediationStatus string `json:"remediation_status"`
}
