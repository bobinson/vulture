package repository

import (
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/model"
)

// activeStatusArgs returns model.ActiveLineageStatuses as query arguments, in
// the same order activeStatusIn renders its placeholders.
func activeStatusArgs() []interface{} {
	statuses := model.ActiveLineageStatuses()
	args := make([]interface{}, 0, len(statuses))
	for _, s := range statuses {
		args = append(args, string(s))
	}
	return args
}

// activeStatusIn renders the parenthesised placeholder list for an
// `IN (...)` filter over model.ActiveLineageStatuses. numbered selects
// Postgres' `$n` form, starting at start; otherwise SQLite's positional `?`.
// Both dialects build their filter here so they can never disagree about which
// statuses are active.
func activeStatusIn(numbered bool, start int) string {
	placeholders := make([]string, len(model.ActiveLineageStatuses()))
	for i := range placeholders {
		placeholders[i] = "?"
		if numbered {
			placeholders[i] = "$" + strconv.Itoa(start+i)
		}
	}
	return "(" + strings.Join(placeholders, ",") + ")"
}

// notMerged is the one clause every lineage QUERY carries (feature 0091 §5.4
// step 5). A row with `merged_into` set lost a duplicate merge: it is the same
// finding as its survivor, recorded twice because the tree was scanned under
// two path forms. Returning it would double-count it in the aggregate, run the
// evidence check on it twice, and let one half be `fixed` while the other
// stays `open`.
//
// It is a constant appended by every query rather than a phrase re-typed per
// query, because the failure mode of a missed copy is silent: the duplicate
// simply reappears in one endpoint.
//
// THREE READS DELIBERATELY DO NOT CARRY IT, and each omission is load-bearing:
//
//   - GetLineage(id): the loser is MARKED, not deleted, precisely so a stale
//     VLT link still leads somewhere.
//   - GetLineageByFingerprint / GetLineageByFingerprints: these are not report
//     reads, they are the probe that decides INSERT vs UPDATE for a stored
//     identity. A merged loser still occupies (fingerprint, source_path,
//     agent_type) — uq_lineage is deliberately kept for the
//     VULTURE_LINEAGE_KEY=path rollback — so hiding it would make the writer
//     insert a second row on the same unique key: an error on Postgres, and a
//     silent duplicate on SQLite, whose twin of that index is not unique.
//
// The target-keyed matcher (GetLineageByFingerprintsForTarget) DOES carry it:
// there the survivor is in the same group and is the right answer, so
// selecting the retired loser would resurrect exactly what the merge retired.
const notMerged = " AND merged_into IS NULL"

// lineageSelectCols renders the SELECT list every lineage read shares, in the
// exact order scanLineageInto expects.
//
// It is a function rather than eleven copies of a 25-column list because
// feature 0091 added eleven columns to a list that was already duplicated six
// times per dialect: any copy that drifts produces a scan error at runtime, in
// one query only, discovered by whichever endpoint happens to run it. prefix
// is "" for a bare table and "fl." for the joined ListByAudit query; pg picks
// the ::text casts Postgres needs for its UUID columns and SQLite does not
// understand.
func lineageSelectCols(prefix string, pg bool) string {
	txt := func(col string) string {
		if pg {
			return "COALESCE(" + prefix + col + "::text,'')"
		}
		return "COALESCE(" + prefix + col + ",'')"
	}
	p := func(col string) string { return prefix + col }
	return strings.Join([]string{
		p("id"), p("fingerprint"), p("source_path"), p("agent_type"), p("current_status"),
		"COALESCE(" + p("notes") + ",'')", "COALESCE(" + p("ticket_url") + ",'')",
		p("first_audit_id"), p("first_found_at"), "COALESCE(" + p("first_commit") + ",'')",
		txt("latest_audit_id"), p("latest_found_at"), "COALESCE(" + p("latest_commit") + ",'')",
		txt("fixed_audit_id"), p("fixed_at"), "COALESCE(" + p("fixed_commit") + ",'')",
		p("severity"), p("category"), p("title"), p("file_path"), p("created_at"), p("updated_at"),
		"COALESCE(" + p("ref_number") + ", 0)",
		// Feature 0091 (migration 027). Appended, never interleaved, so a
		// mismatch between this list and a scan target is a compile-time
		// ordering question rather than a silent column shift.
		"COALESCE(" + p("target_key") + ",'')",
		"COALESCE(" + p("fingerprint_v2") + ",'')",
		"COALESCE(" + p("git_branch") + ",'')",
		"COALESCE(" + p("provenance") + ",'')",
		"COALESCE(" + p("quote_hash") + ",'')",
		"COALESCE(" + p("evidence_line_start") + ", 0)",
		"COALESCE(" + p("evidence_line_end") + ", 0)",
		"COALESCE(" + p("evidence_file_hash") + ",'')",
		"COALESCE(" + p("seen_count") + ", 1)",
		txt("last_seen_audit_id"),
		txt("merged_into"),
	}, ", ")
}

// indexLineageByIdentity keys rows for the target-scoped lookup by BOTH
// identities a finding may arrive under: `<fingerprint>|<agent>` and
// `<fingerprint_v2>|<agent>`.
//
// Both, not one, because the two tiers do not agree about which they send: a
// rescan under a new mount reports the same v2 with a NEW v1, so a v1-only
// index misses the row and mints a duplicate; and 31,153 persisted findings
// carry no v2 at all, so a v2-only index misses those. The v1 entry is written
// second so it never displaces a v2 match on the same key.
//
// Shared by both dialects: the map shape is part of what resolveExisting
// expects, and two copies of it would drift.
func indexLineageByIdentity(rows []model.FindingLineage) map[string]*model.FindingLineage {
	out := make(map[string]*model.FindingLineage, 2*len(rows))
	for i := range rows {
		row := &rows[i]
		if row.FingerprintV2 != "" {
			out[row.FingerprintV2+"|"+row.AgentType] = row
		}
	}
	for i := range rows {
		row := &rows[i]
		key := row.Fingerprint + "|" + row.AgentType
		if _, taken := out[key]; !taken {
			out[key] = row
		}
	}
	return out
}

// defaultSeenCount floors a lineage row's seen_count at 1. A row that exists
// was seen at least once, by the scan that created it; storing 0 would make
// the aggregate's "seen in N scans" column read as never-seen for every row
// created before the column existed.
func defaultSeenCount(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// LineageEvidenceUpdate carries the outcome of one agent-side evidence check
// onto a lineage row (feature 0091 §6.4). It is one struct rather than seven
// parameters because the fields are not independent: IncrementSeen is false
// for `ambiguous`, UpdateWindow is false unless re-anchoring is armed, and a
// caller passing them positionally would eventually transpose two.
type LineageEvidenceUpdate struct {
	// AuditID is the scan that made the observation.
	AuditID string
	// FileHash is sha256 of the cited file as the agent read it this scan.
	FileHash string
	// IncrementSeen raises seen_count. True only when the scan POSITIVELY
	// observed the code — never for `ambiguous`, and never on an error path.
	IncrementSeen bool
	// LineStart/LineEnd is the re-anchored window, applied only when
	// UpdateWindow is set (VULTURE_LLM_QUOTE_REANCHOR).
	LineStart    int
	LineEnd      int
	UpdateWindow bool
}

// LineageRepository defines persistence operations for finding lineage tracking.
type LineageRepository interface {
	UpsertLineage(l *model.FindingLineage) error
	GetLineage(id string) (*model.FindingLineage, error)
	GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error)
	GetLineageByFingerprints(fingerprints []string, sourcePath string) (map[string]*model.FindingLineage, error)
	ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error)
	ListByAudit(auditID string) ([]model.FindingLineage, error)
	UpdateStatus(id string, status string, notes string, ticketURL string) error
	MarkFixed(id, auditID, commit string) error
	MarkRegression(id, auditID, commit string) error
	// GetActiveBySourcePath returns the rows a scan of sourcePath may still act
	// on: current_status IN model.ActiveLineageStatuses().
	GetActiveBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error)
	// ActiveByTarget is GetActiveBySourcePath keyed by target identity instead
	// of by the directory the scan happened to run in (feature 0091 §7). It is
	// the default read from P3; VULTURE_LINEAGE_KEY=path restores the
	// path-keyed one as the rollback.
	//
	// The difference is not an optimisation: under the path key a run-mode
	// switch strands every previous scan's rows in a partition nothing will
	// ever query again, so the finding is re-created with a new VLT ref and
	// the triage attached to the old row is orphaned.
	ActiveByTarget(targetKey, agentType string) ([]model.FindingLineage, error)
	// GetLineageByFingerprintsForTarget is GetLineageByFingerprints keyed by
	// target, and matching on EITHER identity: `fingerprint_v2` (the 0079
	// path-canonical id, stable across mounts) or the v1 `fingerprint` (the
	// stable ref id, which embeds the absolute path and therefore is not).
	//
	// Both halves are load-bearing. v2 is what lets a rescan under a new mount
	// recognise the row it already has; v1 is the bridge for the 31,153
	// persisted findings that carry no v2 at all.
	GetLineageByFingerprintsForTarget(fingerprints []string, targetKey string) (map[string]*model.FindingLineage, error)
	// LegacyTargetKey recomputes the string-only key migration 027's step-4
	// backfill attributed to this source path, so the two target-keyed reads
	// above can also reach the rows the backfill keyed.
	//
	// It is a BRIDGE, not a second identity: the backfill runs without git or
	// a filesystem (the paths it keys no longer exist), so it cannot produce
	// the `git:`/`marker:` key the live resolver does, and without the bridge
	// every historical row is invisible to the next scan. See
	// lineage_legacy_key.go for why that failure is silent and what it costs.
	LegacyTargetKey(sourcePath string) (string, error)
	// GetRecentlyFixedBySourcePath returns `fixed` rows from the last
	// `auditWindow` distinct fixing audits of this (source, agent). Feature
	// 0091 §6.3: a fixed LLM row is re-checked for a bounded window so a
	// finding that comes BACK is caught even when the model never mentions it
	// (S11) — an unbounded re-check would re-send every row ever closed.
	GetRecentlyFixedBySourcePath(sourcePath, agentType string, auditWindow int) ([]model.FindingLineage, error)
	// RecentlyFixedByTarget is GetRecentlyFixedBySourcePath keyed by target
	// identity, and it is the default from P3 for the same reason
	// ActiveByTarget is.
	//
	// The path-keyed twin is not merely narrower, it is keyed on the FIRST
	// sighting's mount and nothing ever rewrites `source_path`. So a row
	// closed under /mnt/source/proj is never re-checked by a native scan of
	// /home/x/proj, and for a git source — where every ingest clones into a
	// fresh directory — it is never re-checked at all. That is D3, the exact
	// partitioning §7 exists to remove, surviving in the one read that did
	// not move with the others.
	RecentlyFixedByTarget(targetKey, agentType string, auditWindow int) ([]model.FindingLineage, error)
	// MarkUnconfirmed records that the scan could not decide the row. Distinct
	// from UpdateStatus, which is the USER-facing path and overwrites notes and
	// ticket_url — a scanner transition must never erase human triage text.
	MarkUnconfirmed(id, auditID string) error
	// MarkSeen records that the scan observed the finding, without changing
	// its status: seen_count+1 and last_seen_audit_id.
	MarkSeen(id, auditID string) error
	// ApplyEvidence records an agent-side evidence outcome on the row.
	ApplyEvidence(id string, ev LineageEvidenceUpdate) error
	AddEvent(e *model.LineageEvent) error
	GetEvents(lineageID string) ([]model.LineageEvent, error)

	// ── Feature 0091 P4: the target-scoped read side (§10.1) ───────────────
	//
	// ListTargets is the dashboard: every codebase this installation has
	// scanned, with counts taken from finding_lineage rather than from the
	// last scan's findings.
	ListTargets() ([]model.TargetSummary, error)
	// TargetScans is the history rail for one target, newest first.
	TargetScans(targetKey string) ([]model.TargetScan, error)
	// AggregateByTarget is the report: unique findings for a target, filtered,
	// counted and paged IN SQL, computed from finding_lineage ALONE.
	//
	// The no-join rule is structural, not a target: `findings` holds 93,341
	// rows against finding_lineage's 10,663, and joining it is the difference
	// between a report that opens and one that times out. It is enforced by a
	// test that reads this method's SQL (TestAggregateNoJoinToFindings).
	AggregateByTarget(q model.AggregateQuery) (*model.AggregateReport, error)
	// CountTargetScans is the denominator of "seen in 2 of 5 scans": how many
	// scans are in the selection. Empty `scans` = every scan of the target.
	CountTargetScans(targetKey string, scans []string) (int, error)
	// SeenInAudits is the audits that saw one finding: those that REPORTED it
	// (matched on both 0079 identities in `findings`) plus those the row
	// itself is attributed to, which is how a scan that only RE-READ the
	// evidence is counted. It is the ONLY read in this feature that touches
	// `findings`, and it serves ONE lineage row on the detail endpoint —
	// which is exactly why the aggregate may not do the same thing per row.
	SeenInAudits(l *model.FindingLineage) ([]string, error)
}
