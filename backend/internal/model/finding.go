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
	ID                string   `json:"id"`
	AuditID           string   `json:"audit_id"`
	AgentType         string   `json:"agent_type"`
	Severity          Severity `json:"severity"`
	Category          string   `json:"category"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	FilePath          string   `json:"file_path"`
	LineStart         int      `json:"line_start"`
	LineEnd           int      `json:"line_end"`
	Recommendation    string   `json:"recommendation"`
	References        []string `json:"references,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`
	CheckID           string   `json:"check_id,omitempty"`
	CodeSnippet       string   `json:"code_snippet,omitempty"`
	VerificationHints  []string `json:"verification_hints,omitempty"`
	RequiresContext    bool     `json:"requires_context,omitempty"`
	CrossAgentOrigins  []string `json:"cross_agent_origins,omitempty"`

	// Validation phase (feature 0045). All optional; absent for
	// pre-feature findings or when VULTURE_DISABLE_VALIDATE=true.
	ValidationStatus     string                 `json:"validation_status,omitempty"`
	ValidationConfidence float64                `json:"validation_confidence,omitempty"`
	Validation           map[string]interface{} `json:"validation,omitempty"`
	IsRollup             bool                   `json:"is_rollup,omitempty"`
	RolledUpInto         string                 `json:"rolled_up_into,omitempty"`
	InstanceCount        int                    `json:"instance_count,omitempty"`
}

// PriorFinding is a lightweight summary of a previous finding passed to agents
// so they can skip re-analyzing known issues and save LLM tokens.
// Includes confidence_score, created_at, and prove_status so Python MMR
// selection can use quality-weighted ranking instead of Jaccard fallback.
type PriorFinding struct {
	ID                string  `json:"id,omitempty"`
	AgentType         string  `json:"agent_type,omitempty"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	Category          string  `json:"category"`
	Description       string  `json:"description,omitempty"`
	FilePath          string  `json:"file_path"`
	RemediationStatus string  `json:"remediation_status"`
	ConfidenceScore   float64 `json:"confidence_score,omitempty"`
	CreatedAt         string  `json:"created_at,omitempty"`
	ProveStatus       string  `json:"prove_status,omitempty"`
	CheckID           string  `json:"check_id,omitempty"`
}
