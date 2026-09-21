package model

import (
	"fmt"
	"strings"
	"time"
)

// LineageStatus represents the lifecycle state of a finding across audits.
type LineageStatus string

const (
	LineageStatusOpen          LineageStatus = "open"
	LineageStatusInProgress    LineageStatus = "in_progress"
	LineageStatusResolved      LineageStatus = "resolved"
	LineageStatusAcceptedRisk  LineageStatus = "accepted_risk"
	LineageStatusFalsePositive LineageStatus = "false_positive"
	LineageStatusFixed         LineageStatus = "fixed"
	LineageStatusRegression    LineageStatus = "regression"
	// LineageStatusUnconfirmed (feature 0091) is the state of a row the scan
	// could NOT decide: the agent lost the evidence quote, could not read the
	// file, or its verifier threw. It is deliberately ACTIVE — a terminal
	// "unconfirmed" would be a slower version of the disappearance 0091 exists
	// to prevent — and it is never reached by absence alone.
	LineageStatusUnconfirmed LineageStatus = "unconfirmed"
)

// ActiveLineageStatuses returns every status a scan is still allowed to act on:
// the row describes a finding that is believed to be present in the code.
//
// This is the ONE definition of "active". Nothing else may enumerate active
// statuses inline — the repository filters, the aggregate queries and the
// partial indexes all build their IN clause from this slice, so they cannot
// drift apart. `regression` belongs here: a regressed finding is present again,
// so a later scan that no longer sees it must be able to close it (feature 0091
// D1b). The user-decided terminals (`resolved`, `accepted_risk`,
// `false_positive`) and the scanner-set terminal (`fixed`) are deliberately
// absent.
//
// A fresh slice is returned on every call so a caller cannot mutate the set.
func ActiveLineageStatuses() []LineageStatus {
	return []LineageStatus{
		LineageStatusOpen,
		LineageStatusInProgress,
		LineageStatusRegression,
		LineageStatusUnconfirmed,
	}
}

// Finding tiers. The tier decides which closure rule a lineage row obeys:
// deterministic rows close on absence (absence is reproducible for a skill),
// LLM rows close only on evidence (feature 0091 §4).
const (
	TierLLM           = "llm"
	TierDeterministic = "det"
)

// TierOf derives a finding's tier from its provenance. Feature 0091 §5.1: the
// tier is DERIVED, never stored as a second source of truth.
//
// "llm" iff the provenance starts with `llm` (llm, llm_l5_verified,
// llm_tier3, …). EVERYTHING else is deterministic: `skill`, `catalog_rollup`,
// `signature_trusted`, every plugin provenance — and the EMPTY string, which
// 5,750 persisted findings carry because they predate the field. Defaulting
// empty to `det` is the safe direction: a det row closes on absence, which is
// exactly the behaviour those rows have had all along, so the tier rule cannot
// silently change history for them.
func TierOf(provenance string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(provenance)), TierLLM) {
		return TierLLM
	}
	return TierDeterministic
}

// MemoryStatusForLineage maps a lineage status onto the
// `audit_memories.remediation_status` value that must accompany it (feature
// 0091 §8). Only `resolved` removes a memory from the prior-findings block, so
// `false_positive` and `accepted_risk` map to themselves and stay in the block
// (S13) — the model must not be invited to re-report a dismissed finding.
func MemoryStatusForLineage(s LineageStatus) string {
	switch s {
	case LineageStatusFixed, LineageStatusResolved:
		return "resolved"
	case LineageStatusFalsePositive:
		return "false_positive"
	case LineageStatusAcceptedRisk:
		return "accepted_risk"
	default:
		// open, in_progress, regression, unconfirmed — all still live.
		return "open"
	}
}

// LineageEventType describes what happened to a lineage record.
type LineageEventType string

const (
	LineageEventDetected     LineageEventType = "detected"
	LineageEventStatusChange LineageEventType = "status_change"
	LineageEventFixed        LineageEventType = "fixed"
	LineageEventRegression   LineageEventType = "regression"
	LineageEventNoteAdded    LineageEventType = "note_added"

	// Feature 0091. Each of these records WHY a scan did or did not act on a
	// row, so a reader can tell "the scan saw the code" apart from "the model
	// stopped mentioning it" — the distinction the whole feature turns on.
	//
	// LineageEventConfirmedByEvidence: the agent re-read the cited file and
	// found the stored quote. The row is carried forward.
	LineageEventConfirmedByEvidence LineageEventType = "confirmed_by_evidence"
	// LineageEventEvidenceGone: the quote is no longer in the cited file. This
	// is the ONLY way an LLM-tier row closes.
	LineageEventEvidenceGone LineageEventType = "evidence_gone"
	// LineageEventUnconfirmable: the check could not be decided (lost quote,
	// unreadable file, verifier exception, or no check returned at all).
	LineageEventUnconfirmable LineageEventType = "unconfirmable"
	// LineageEventSkippedDegraded: the run lost the tier that owns this row
	// (S19), so nothing about it was observed.
	LineageEventSkippedDegraded LineageEventType = "skipped_degraded"
	// LineageEventOutOfScope: the scan could not have seen this path (sub-path
	// scan, pruned directory, truncated enumeration) — S14, S15, S20.
	LineageEventOutOfScope LineageEventType = "out_of_scope"
	// LineageEventAbsentInResult: present in spirit but missing from the
	// result for a structural reason (e.g. a rollup parent swallowed its leaf,
	// 0090 GR6) — recorded rather than treated as repair (S21).
	LineageEventAbsentInResult LineageEventType = "absent_in_result"
	// LineageEventScopeUnknown: the agent did not speak the 0091 protocol
	// (`result_schema` absent or < 2), so the backend cannot know what the scan
	// was able to see. No LLM-tier or pruned-dir closure may follow (S26).
	LineageEventScopeUnknown LineageEventType = "scope_unknown"
	// LineageEventMemorySynced: the row's status was propagated to
	// audit_memories.remediation_status (§8).
	LineageEventMemorySynced LineageEventType = "memory_synced"
	// LineageEventMerged: this row absorbed a duplicate during the 027
	// target-identity merge (§5.4 step 5, lands in P3).
	LineageEventMerged LineageEventType = "merged"
	// LineageEventReported: the scan REPORTED this finding again. Informational
	// (status unchanged) and the most common observation there is — and until
	// feature 0091's follow-up the only one that left no trace. A re-find only
	// bumped seen_count, so the newest event on a row stayed whatever the
	// previous scan had said; the aggregate read that as the LAST observation
	// and showed "Outside the scan's scope" under a row the latest scan had
	// just re-found. Written by scanPass.markSeen, admitted by migration 029.
	LineageEventReported LineageEventType = "reported"
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
	RefNumber     int           `json:"ref_number"`
	Ref           string        `json:"ref,omitempty"`

	// ── Feature 0091 (migration 027) ───────────────────────────────────────
	// TargetKey is the canonical target identity that will replace SourcePath
	// as the partition key. Written from P3; carried here so the column and
	// the struct land together.
	TargetKey string `json:"target_key,omitempty"`
	// FingerprintV2 is the 0079 canonical identity, the matching key from P3.
	FingerprintV2 string `json:"fingerprint_v2,omitempty"`
	// GitBranch is the branch of the scan that last saw the row. Closure is
	// per branch (§7.4, S24): a scan of another branch may confirm a row but
	// never close it.
	GitBranch string `json:"git_branch,omitempty"`
	// Provenance is the provenance of the finding that created the row. It is
	// the ONLY input to TierOf, and therefore decides whether this row closes
	// on absence or only on evidence.
	Provenance string `json:"provenance,omitempty"`
	// QuoteHash is sha256 of the whitespace-normalised evidence quote. The
	// quote text itself never leaves the agent; this hash is what lets the
	// agent prove its local cache entry belongs to this row.
	QuoteHash string `json:"quote_hash,omitempty"`
	// EvidenceLineStart/End is the window verified at the last confirmation.
	EvidenceLineStart int `json:"evidence_line_start,omitempty"`
	EvidenceLineEnd   int `json:"evidence_line_end,omitempty"`
	// EvidenceFileHash is sha256 of the cited file at last confirmation or at
	// fix; it bounds the fixed-row re-check (§6.3).
	EvidenceFileHash string `json:"evidence_file_hash,omitempty"`
	// SeenCount counts scans that re-found the finding OR positively confirmed
	// its code is still present. A scan that observed nothing never raises it.
	SeenCount int `json:"seen_count"`
	// LastSeenAuditID lets the aggregate report "last seen" without a join.
	LastSeenAuditID string `json:"last_seen_audit_id,omitempty"`
	// MergedInto is set on the loser of a duplicate merge (P3); such a row is
	// excluded from every read.
	MergedInto string `json:"merged_into,omitempty"`
}

// FormatRef returns the human-readable reference string (e.g. "VLT-0042").
func (l *FindingLineage) FormatRef() string {
	if l.RefNumber <= 0 {
		return ""
	}
	return fmt.Sprintf("VLT-%04d", l.RefNumber)
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
