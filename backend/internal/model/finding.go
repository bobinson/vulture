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
	Provenance        string   `json:"provenance,omitempty"`
	VerificationHints []string `json:"verification_hints,omitempty"`
	RequiresContext   bool     `json:"requires_context,omitempty"`
	CrossAgentOrigins []string `json:"cross_agent_origins,omitempty"`

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
	// Evidence carried so a MAPPING agent (OWASP over CWE, feature 0063) can
	// inherit it instead of emitting a stripped row. Without these, every OWASP
	// finding reached the DB with an empty provenance — 217 of 217 on the
	// reference target across three runs — and widening the agent's own carry
	// set could not fix it, because the transport never delivered the values.
	//
	// `code_snippet` remains absent by design (see the note below): the point of
	// carrying provenance is attribution, which needs no source text.
	Provenance           string  `json:"provenance,omitempty"`
	ValidationStatus     string  `json:"validation_status,omitempty"`
	ValidationConfidence float64 `json:"validation_confidence,omitempty"`
	// Line location, carried so mapping agents (e.g. OWASP over CWE,
	// feature 0063) keep the source location. code_snippet is deliberately
	// NOT carried here — snippets can contain secrets.
	LineStart int `json:"line_start,omitempty"`
	LineEnd   int `json:"line_end,omitempty"`
}
