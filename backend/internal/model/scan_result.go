package model

// Feature 0091 §6.1 — the versioned wire contract between the backend and an
// agent, in both directions.
//
// WHY IT IS VERSIONED. Before 0091 an agent's `result` event told the backend
// what it FOUND and nothing about what it LOOKED AT. Absence of a finding was
// therefore indistinguishable from "the walker never opened that directory",
// "the LLM phase died", and "the model was told to skip it" — and the backend
// read all three as repair. The two keys below close that gap, and an agent
// that cannot send them must not be trusted to close anything in the LLM tier:
// `result_schema` absent (or < 2) means OLD AGENT, which the backend treats as
// unknown scope (S26).

// ScanResultSchemaEvidence is the result-event schema version that carries
// scope (`pruned_dirs`) and evidence (`lineage_checks`). A result below it is
// parsed exactly as before and grants no LLM-tier closure.
const ScanResultSchemaEvidence = 2

// Lineage check outcomes, as the agent reports them (§6.2). The set is closed:
// anything else is treated as unconfirmable, because an outcome the backend
// does not understand is not evidence.
const (
	// LineageOutcomeConfirmed — the quote is where the row says it is.
	LineageOutcomeConfirmed = "confirmed"
	// LineageOutcomeReanchored — the quote is elsewhere in the same file.
	LineageOutcomeReanchored = "reanchored"
	// LineageOutcomeAmbiguous — several equally plausible matches; the finding
	// is still there, but the window cannot be pinned.
	LineageOutcomeAmbiguous = "ambiguous"
	// LineageOutcomeGone — the file was read and the quote is not in it. The
	// only outcome that closes a row.
	LineageOutcomeGone = "gone"
	// LineageOutcomeUnconfirmable — the check could not be made: no cached
	// quote, hash mismatch, unreadable/oversize/binary file, or the verifier
	// threw. NEVER a fix; a crash in the checker must not be able to close a
	// codebase (S25).
	LineageOutcomeUnconfirmable = "unconfirmable"
)

// LineageCheck is one row of the result event's `lineage_checks` array: the
// agent's verdict on one lineage row it was asked about.
type LineageCheck struct {
	LineageID string `json:"lineage_id"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason,omitempty"`
	LineStart int    `json:"line_start,omitempty"`
	LineEnd   int    `json:"line_end,omitempty"`
	FileHash  string `json:"file_hash,omitempty"`
}

// ScanResult is the agent's `result` event, read for everything the closure
// pass needs. It is deliberately tolerant: every 0091 field is optional, so an
// old agent's payload decodes into a zero ResultSchema and empty slices rather
// than an error.
type ScanResult struct {
	// ResultSchema is 0 for every agent built before 0091.
	ResultSchema int `json:"result_schema,omitempty"`
	// PrunedDirs lists the root-relative prefixes the walker skipped this run.
	// A lineage row under one of them is out of scope, not fixed (S15).
	PrunedDirs []string `json:"pruned_dirs,omitempty"`
	// LineageChecks answers the `lineage_checks_requested` block.
	LineageChecks []LineageCheck `json:"lineage_checks,omitempty"`
	// Findings and Score are the pre-0091 payload, unchanged.
	Findings []Finding `json:"findings"`
	Score    float64   `json:"score,omitempty"`
	// DegradedReason names a phase the run LOST but survived (feature 0070
	// P5 A.3). A degraded run cannot close anything in the tier that degraded.
	DegradedReason string `json:"degraded_reason,omitempty"`
	// ScanTruncated is set when the walker hit VULTURE_MAX_FILES, so the
	// enumerated set is partial and absence proves nothing (S20).
	ScanTruncated bool `json:"scan_truncated,omitempty"`

	// NoResultSnapshot marks a result the BACKEND synthesised for an agent
	// that was dispatched and never sent one — killed by
	// VULTURE_AGENT_PROXY_TIMEOUT_SEC, cancelled on client disconnect, or
	// crashed. Its findings are then rescued from the delta stream, which is
	// by construction a PARTIAL set.
	//
	// It is `json:"-"` on purpose: no agent can set it, and an agent that
	// COMPLETED always leaves a snapshot behind (a pre-0091 one decodes to
	// ResultSchema 0, which is a different state — "old agent", S26 — and
	// keeps its deterministic closures). Folding the two together is what let
	// a timed-out agent close every deterministic row it did not manage to
	// re-report.
	NoResultSnapshot bool `json:"-"`

	// RollupShadowed holds the fingerprints cross-agent dedup removed because
	// a ROLLUP PARENT covering the same site survived in their place
	// (§6.3, S21). Also backend-set and unparsed: the agent reported those
	// findings, the backend consolidated them, and reading their absence from
	// the persisted result as repair would close a finding for a purely
	// structural reason.
	//
	// It is global to the run rather than per agent because the parent and
	// the leaf it shadows are routinely different agents.
	RollupShadowed map[string]bool `json:"-"`
}

// HasEvidenceProtocol reports whether the agent that produced this result
// speaks 0091. Nil-safe: a missing result is an old agent by definition.
func (r *ScanResult) HasEvidenceProtocol() bool {
	return r != nil && r.ResultSchema >= ScanResultSchemaEvidence
}

// LineageCheckRequest is one row of the audit request's
// `lineage_checks_requested.rows`: "here is a finding I believe is in your
// tree — go and look".
//
// It carries a HASH of the evidence quote, never the quote. The text lives
// only in the agent's local cache; the backend has never seen it and 0091 does
// not change that.
type LineageCheckRequest struct {
	LineageID     string `json:"lineage_id"`
	FingerprintV2 string `json:"fingerprint_v2"`
	RelPath       string `json:"rel_path"`
	LineStart     int    `json:"line_start"`
	LineEnd       int    `json:"line_end"`
	QuoteHash     string `json:"quote_hash"`
	// Status is `open` for an active row and `fixed` for one of the bounded
	// re-checks (§6.3) — the agent needs it to know that finding the quote is
	// news (a regression), not confirmation.
	Status   string `json:"status"`
	FileHash string `json:"file_hash,omitempty"`
}

// LineageChecksRequestSchema is the version of the request block. Separate
// from the result schema: the two evolve independently.
const LineageChecksRequestSchema = 1

// LineageChecksRequest is the audit request's `lineage_checks_requested` key.
type LineageChecksRequest struct {
	Schema int                   `json:"schema"`
	Rows   []LineageCheckRequest `json:"rows"`
}
