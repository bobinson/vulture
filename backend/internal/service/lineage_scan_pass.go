package service

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0091 §6.3-§6.4 — what a scan's silence about a lineage row means.
//
// THE PRINCIPLE. Absence from an LLM result is never evidence. The prior-
// findings block explicitly instructs the model to "skip known issues and
// report NEW findings only", and the model complies; on top of that the tier
// re-finds an unknown finding about one time in twenty. So for an LLM-tier row
// there are three indistinguishable reasons it is missing from a result —
// suppressed, non-reproducible, or actually fixed — and only the last is
// repair. Closure therefore comes from the CODE: the quote stored when the
// finding was raised, re-verified against the current file by the agent that
// has both, and reported back as a `lineage_checks` row.
//
// The deterministic tier keeps the old rule unchanged, and that asymmetry is
// the point rather than an inconsistency: a skill's absence IS reproducible,
// so for it absence is meaningful. Every branch below that stops a closure is
// scoped to the LLM tier, which is why several tests carry a deterministic row
// alongside the LLM one — a change that merely stopped closing everything
// would be a regression, not a fix.

// scanPass is one (audit, agent_type) closure pass. It holds only reads taken
// before the pass began writing, so nothing it decides can depend on a write
// it made earlier in the same loop.
type scanPass struct {
	svc       *lineageService
	audit     *model.Audit
	source    *model.Source
	agentType string
	// present holds every fingerprint this scan reported for the agent.
	present map[string]bool
	// checks indexes the agent's evidence outcomes by lineage id.
	checks map[string]model.LineageCheck
	// scope is nil when the agent did not tell us what it looked at.
	scope *scanScope
	// llmEnabled is false when the run lost its LLM phase (S19).
	llmEnabled bool
	degraded   string
	// targetKeyed is false under the VULTURE_LINEAGE_KEY=path rollback.
	targetKeyed bool
	// noResult is true when the agent was dispatched and never reported at
	// all, so its finding set is a partial delta rescue rather than a result.
	noResult bool
	// shadowed holds the fingerprints cross-agent dedup replaced with a
	// rollup parent covering the same site (S21).
	shadowed map[string]bool
}

// apply decides one row.
//
// The order is the contract. Reporting is tested BEFORE the branch guard,
// because §7.4 splits the two questions: grouping is per target, closure is
// per branch, and a scan of another branch may CONFIRM a row it re-found even
// though it may never close one it did not (S24). Testing the branch first
// would silently drop the sighting.
func (p *scanPass) apply(row *model.FindingLineage) {
	if p.skip(row) {
		return
	}
	if p.reported(row) {
		p.markSeen(row)
		return
	}
	if p.rollupShadowed(row) {
		// The agent DID report this finding; cross-agent dedup then replaced
		// it with a rollup parent covering the same site. It is absent from
		// the persisted result for a structural reason, not because the code
		// changed (§6.3, S21).
		p.event(row, model.LineageEventAbsentInResult, absentReasonRollupParent, row.CurrentStatus)
		return
	}
	if !sameBranch(row, p.source) {
		// A file that is absent because you are standing on another branch has
		// not been fixed; the commit that removed it may not even exist.
		return
	}
	if p.noResult {
		// The agent was dispatched and never reported. Its findings reached us
		// through the delta rescue, which is a PARTIAL set by construction, so
		// this scan cannot say it looked at anything — the same reading a nil
		// scope and a truncated enumeration already get, applied to BOTH tiers.
		p.event(row, model.LineageEventScopeUnknown, scopeReasonNoResult, row.CurrentStatus)
		return
	}
	if reason := p.scope.exclusion(row.FilePath); reason != "" {
		p.event(row, model.LineageEventOutOfScope, reason, row.CurrentStatus)
		return
	}
	if model.TierOf(row.Provenance) == model.TierDeterministic {
		p.closeDeterministic(row)
		return
	}
	p.applyLLM(row)
}

// reported answers "did this scan report this finding", under either identity
// (§7.3). fingerprint_v2 first, v1 as the fallback for rows that predate it.
//
// The v2 arm is what stops S16: a rescan of the same tree under a new mount
// emits a NEW v1 for an unchanged finding, so a v1-only test reads it as
// absent and the deterministic rule closes it. Under
// VULTURE_LINEAGE_KEY=path the pre-0091 v1-only test is restored, because a
// path-keyed pass never sees rows from another mount in the first place.
func (p *scanPass) reported(row *model.FindingLineage) bool {
	if p.targetKeyed && row.FingerprintV2 != "" && p.present[row.FingerprintV2] {
		return true
	}
	return p.present[row.Fingerprint]
}

// rollupShadowed answers "did this scan report the finding and then have it
// consolidated away". Both identities are consulted for the same reason
// reported() consults both.
func (p *scanPass) rollupShadowed(row *model.FindingLineage) bool {
	if len(p.shadowed) == 0 {
		return false
	}
	return p.shadowed[row.Fingerprint] ||
		(row.FingerprintV2 != "" && p.shadowed[row.FingerprintV2])
}

// skip covers the rows no scan may touch, whatever it found.
//
//   - merged_into: the row lost a duplicate merge and is invisible to reads.
//   - a user-decided status (accepted_risk, false_positive, resolved): a human
//     ruled on it and the scanner does not get a vote.
//
// The per-branch guard is NOT here: it bars closure, not observation, so it
// sits in apply after the sighting has been recorded (§7.4, S24).
func (p *scanPass) skip(row *model.FindingLineage) bool {
	return row.MergedInto != "" || userDecided(row.CurrentStatus)
}

// applyLLM is the evidence path. Every early return here is a refusal to act,
// and each one is a scenario the naive rule gets wrong.
func (p *scanPass) applyLLM(row *model.FindingLineage) {
	if p.scope == nil {
		// The agent predates 0091: it cannot report scope and cannot report
		// evidence, so there is nothing here but silence (S26).
		p.event(row, model.LineageEventScopeUnknown, "agent did not report result_schema >= 2", row.CurrentStatus)
		return
	}
	if !p.llmEnabled {
		// The run lost the very tier that owns this row, so the row was not
		// observed at all (S19).
		p.event(row, model.LineageEventSkippedDegraded, p.degraded, row.CurrentStatus)
		return
	}
	check, ok := p.checks[row.ID]
	if !ok {
		// The row was asked about and nothing came back. An agent that drops a
		// row must not be able to close it by omission.
		p.markUnconfirmed(row, "missing")
		return
	}
	p.applyCheck(row, check)
}

// applyCheck maps one agent outcome onto a transition (§6.4). An outcome the
// backend does not recognise falls through to unconfirmable, because an
// unparsed verdict is not evidence.
func (p *scanPass) applyCheck(row *model.FindingLineage, check model.LineageCheck) {
	switch check.Outcome {
	case model.LineageOutcomeConfirmed, model.LineageOutcomeReanchored, model.LineageOutcomeAmbiguous:
		p.applyEvidencePresent(row, check)
	case model.LineageOutcomeGone:
		p.applyEvidenceGone(row, check)
	default:
		p.markUnconfirmed(row, check.Reason)
	}
}

// applyEvidencePresent handles the outcomes that say "the code is still
// there": the row is carried forward unchanged, or — if it had been closed —
// reopened as a regression.
func (p *scanPass) applyEvidencePresent(row *model.FindingLineage, check model.LineageCheck) {
	if row.CurrentStatus == model.LineageStatusFixed && check.Outcome == model.LineageOutcomeConfirmed {
		p.markRegression(row, "evidence_returned")
		return
	}
	// `ambiguous` does NOT raise seen_count: several equally plausible matches
	// means the scan could not say it observed THIS finding.
	// The window moves only under VULTURE_LLM_QUOTE_REANCHOR, because moving a
	// correct line to a wrong one is the one way evidence checking could lose
	// a finding rather than save one.
	if err := p.svc.repo.ApplyEvidence(row.ID, repository.LineageEvidenceUpdate{
		AuditID:       p.audit.ID,
		FileHash:      check.FileHash,
		IncrementSeen: check.Outcome != model.LineageOutcomeAmbiguous,
		LineStart:     check.LineStart,
		LineEnd:       check.LineEnd,
		UpdateWindow:  check.Outcome == model.LineageOutcomeReanchored && reanchorEnabled(),
	}); err != nil {
		log.Printf("[lineage] apply evidence id=%s: %v", row.ID, err)
		return
	}
	p.event(row, model.LineageEventConfirmedByEvidence, evidenceReason(check), row.CurrentStatus)
}

// applyEvidenceGone is the ONLY way an LLM-tier row closes: the agent read the
// file and the quote is not in it.
func (p *scanPass) applyEvidenceGone(row *model.FindingLineage, check model.LineageCheck) {
	if row.CurrentStatus == model.LineageStatusFixed {
		return // already closed; re-confirming the absence changes nothing
	}
	if err := p.svc.repo.MarkFixed(row.ID, p.audit.ID, p.commit()); err != nil {
		log.Printf("[lineage] mark fixed id=%s: %v", row.ID, err)
		return
	}
	_ = p.svc.repo.ApplyEvidence(row.ID, repository.LineageEvidenceUpdate{
		AuditID:  p.audit.ID,
		FileHash: check.FileHash,
	})
	p.event(row, model.LineageEventEvidenceGone, evidenceReason(check), model.LineageStatusFixed)
	p.svc.syncMemory(row, model.LineageStatusFixed)
}

// closeDeterministic is the pre-0091 rule, unchanged: a skill's absence from
// an in-scope scan means the code is gone.
func (p *scanPass) closeDeterministic(row *model.FindingLineage) {
	if err := p.svc.repo.MarkFixed(row.ID, p.audit.ID, p.commit()); err != nil {
		log.Printf("[lineage] mark fixed error id=%s: %v", row.ID, err)
		return
	}
	p.event(row, model.LineageEventFixed, "", model.LineageStatusFixed)
	p.svc.syncMemory(row, model.LineageStatusFixed)
}

// markSeen records that the scan re-reported the finding: the sighting on the
// row (seen_count, last_seen_audit_id) AND a `reported` event on the timeline.
//
// The event is not decoration. The aggregate labels each row with its newest
// event as "what the last scan observed"; every other observation writes one,
// and a re-find that does not leaves the previous scan's verdict standing —
// measured live as "Outside the scan's scope" under a row the latest root scan
// had just re-found. The status is unchanged, so old and new status are equal,
// exactly like the other informational events.
func (p *scanPass) markSeen(row *model.FindingLineage) {
	if err := p.svc.repo.MarkSeen(row.ID, p.audit.ID); err != nil {
		log.Printf("[lineage] mark seen id=%s: %v", row.ID, err)
	}
	p.event(row, model.LineageEventReported, "", row.CurrentStatus)
}

func (p *scanPass) markRegression(row *model.FindingLineage, reason string) {
	if err := p.svc.repo.MarkRegression(row.ID, p.audit.ID, p.commit()); err != nil {
		log.Printf("[lineage] mark regression id=%s: %v", row.ID, err)
		return
	}
	p.event(row, model.LineageEventRegression, reason, model.LineageStatusRegression)
	p.svc.syncMemory(row, model.LineageStatusRegression)
}

// markUnconfirmed is the resolution of every "could not decide" outcome. It
// never closes and never confirms: the row stays active and visible, flagged
// as something the scan failed to settle. A crash in the checker is the
// cheapest possible way to silently close a whole codebase, so no error path
// is allowed to reach `fixed`.
func (p *scanPass) markUnconfirmed(row *model.FindingLineage, reason string) {
	if row.CurrentStatus == model.LineageStatusFixed {
		return // a fixed row is not made worse by an undecidable re-check
	}
	if err := p.svc.repo.MarkUnconfirmed(row.ID, p.audit.ID); err != nil {
		log.Printf("[lineage] mark unconfirmed id=%s: %v", row.ID, err)
		return
	}
	p.event(row, model.LineageEventUnconfirmable, reason, model.LineageStatusUnconfirmed)
	p.svc.syncMemory(row, model.LineageStatusUnconfirmed)
}

// event appends one timeline entry. newStatus equals the old one for the
// purely informational events (out_of_scope, scope_unknown, skipped_degraded,
// confirmed_by_evidence) — they record what the scan OBSERVED, not a change.
func (p *scanPass) event(row *model.FindingLineage, kind model.LineageEventType, notes string, newStatus model.LineageStatus) {
	_ = p.svc.repo.AddEvent(&model.LineageEvent{
		LineageID: row.ID,
		EventType: kind,
		AuditID:   p.audit.ID,
		OldStatus: string(row.CurrentStatus),
		NewStatus: string(newStatus),
		GitCommit: p.commit(),
		GitBranch: p.branch(),
		Notes:     notes,
	})
}

func (p *scanPass) commit() string {
	if p.source == nil {
		return ""
	}
	return p.source.GitCommitShort
}

func (p *scanPass) branch() string {
	if p.source == nil {
		return ""
	}
	return p.source.GitBranch
}

// scanScope is what the scan was able to see: the scanned root minus every
// prefix the walker pruned. It exists because unifying lineage partitions
// makes the scope check load-bearing — today a sub-path scan cannot damage a
// root finding only because they live in separate partitions.
type scanScope struct {
	pruned    []string
	truncated bool
	// offset is where the scan STOOD relative to the target root, "" when it
	// stood on the root itself (§7.2). It is the half of scope that only
	// matters once target identity exists: before it, a scan of <root>/sub
	// could not damage a row under <root>/other because the two lived in
	// different partitions. Now they share one, and this is what replaces the
	// accident (S14).
	offset string
	// root is the target root every comparison is made in. It is needed
	// because `file_path` is stored in TWO forms — absolute for the ~77% of
	// rows written by the deterministic tier, root-relative for the rest —
	// while `pruned_dirs` and the offset are only ever root-relative. Without
	// it an absolute row can never match a pruned prefix, so a scan that
	// refused to enter .vscode still closed the finding inside it (S15).
	root string
}

// newScanScope returns nil when the agent did not tell us what it looked at.
// nil is not "everything": it is "unknown", and an unknown scope closes
// nothing in the LLM tier (S26).
func newScanScope(result *model.ScanResult, target TargetIdentity) *scanScope {
	if !result.HasEvidenceProtocol() {
		return nil
	}
	offset := normalizeRel(target.Offset)
	pruned := make([]string, 0, len(result.PrunedDirs))
	for _, d := range result.PrunedDirs {
		// The agent reports prefixes relative to the directory it walked, so
		// a sub-path scan's "node_modules" is "<offset>/node_modules" in the
		// target's coordinates — the same coordinates the lineage rows use.
		if n := joinRel(offset, normalizeRel(d)); n != "" {
			pruned = append(pruned, n)
		}
	}
	return &scanScope{pruned: pruned, truncated: result.ScanTruncated, offset: offset, root: target.Root}
}

// joinRel joins an offset and a root-relative path, tolerating an empty
// either side.
func joinRel(offset, rel string) string {
	if offset == "" {
		return rel
	}
	if rel == "" {
		return offset
	}
	return offset + "/" + rel
}

// The reasons a path is not inside what the scan walked. They are recorded on
// the `out_of_scope` event, because "the walker pruned it" and "the row was
// recorded under a different mount" are the same non-closure but very
// different operational facts, and only the note distinguishes them.
const (
	scopeReasonTruncated  = "scan truncated: enumerated set is partial"
	scopeReasonOtherMount = "file_path is absolute and not under the scanned root"
	scopeReasonOutside    = "path is outside the scanned sub-tree"
	scopeReasonPruned     = "path is under pruned prefix "
	// scopeReasonNoResult is the state an agent that never finished leaves
	// behind. Distinct from the pre-0091 "old agent" reading, which is a scan
	// that COMPLETED and simply cannot describe its scope.
	scopeReasonNoResult = "agent produced no result snapshot"
)

// absentReasonRollupParent is why a reported finding can be missing from the
// persisted result without the code having changed (S21).
const absentReasonRollupParent = "consolidated into a rollup parent covering the same site"

// contains reports whether a path was inside what the scan walked. A nil scope
// answers true: scope is unknown, so the scope check makes no claim and the
// tier rules decide alone.
func (s *scanScope) contains(filePath string) bool {
	return s.exclusion(filePath) == ""
}

// exclusion is contains with its reason: "" when the path was inside what the
// scan walked, otherwise why it was not.
func (s *scanScope) exclusion(filePath string) string {
	if s == nil {
		return ""
	}
	if s.truncated {
		// The walker stopped early, so the enumerated set is partial and
		// absence proves nothing about any path (S20).
		return scopeReasonTruncated
	}
	rel, ok := s.place(filePath)
	if !ok {
		return scopeReasonOtherMount
	}
	return s.exclusionWithin(rel)
}

// exclusionWithin decides a path already expressed in target coordinates.
func (s *scanScope) exclusionWithin(rel string) string {
	if !s.underOffset(rel) {
		// The scan stood below this path. Absence from a place the walker
		// never opened is not evidence of anything (S14).
		return scopeReasonOutside
	}
	for _, p := range s.pruned {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return scopeReasonPruned + p
		}
	}
	return ""
}

// place maps a lineage row's stored file_path into the target's coordinate
// system — the one `pruned_dirs` and the offset are expressed in. It reports
// false when the path cannot be placed there at all.
//
// THE CASE THAT MAKES THIS NECESSARY. A row's `file_path` is frozen in the
// coordinates of the scan that first raised it (neither upsert rewrites it),
// and target identity (§7) newly makes rows recorded under OTHER mounts of the
// same target visible to this pass. So a row first seen by a docker run at
// /mnt/source/proj/.vscode/tasks.json is handed to a native scan rooted at
// /home/x/proj, where RelToRoot leaves it absolute and no prefix comparison
// against a root-relative `pruned_dirs` can ever match it. Before this guard
// that row was judged IN scope, and the deterministic rule then closed it:
// P2's pruned-directory protection and P3's unified partitions each passed
// their own tests while jointly re-creating the very incident 0091 exists to
// stop, on the first scan under a changed mount.
//
// Unplaceable is answered as "unknown", and unknown never closes — the same
// reading `newScanScope` already gives a result with no schema (S26) and
// `truncated` gives a partial enumeration (S20). A RELATIVE path is already in
// target coordinates by construction and is placed unchanged; that is the form
// ~23% of the live table uses and it must keep working.
func (s *scanScope) place(filePath string) (string, bool) {
	rel := pathutil.RelToRoot(strings.TrimSpace(filepath.ToSlash(filePath)), s.root)
	if strings.HasPrefix(rel, "/") {
		return "", false
	}
	return normalizeRel(rel), true
}

// underOffset reports whether a target-relative path lies inside the sub-tree
// the scan actually stood in.
func (s *scanScope) underOffset(rel string) bool {
	if s.offset == "" {
		return true
	}
	return rel == s.offset || strings.HasPrefix(rel, s.offset+"/")
}

// normalizeRel puts a path in the one form both sides compare on: forward
// slashes, no leading "./" or "/", no trailing slash.
func normalizeRel(p string) string {
	p = strings.TrimSpace(filepath.ToSlash(p))
	p = strings.TrimPrefix(p, "./")
	return strings.Trim(p, "/")
}

// indexChecks keys the agent's outcomes by lineage id. A duplicate id keeps
// the FIRST outcome: an agent that answers twice about one row has already
// contradicted itself, and picking the later answer would make the result
// depend on array order.
func indexChecks(checks []model.LineageCheck) map[string]model.LineageCheck {
	out := make(map[string]model.LineageCheck, len(checks))
	for _, c := range checks {
		if c.LineageID == "" {
			continue
		}
		if _, seen := out[c.LineageID]; !seen {
			out[c.LineageID] = c
		}
	}
	return out
}

// sameBranch implements per-branch closure (§7.4, S24). A row with no recorded
// branch — every row written before 0091, and every non-git target — closes
// normally: the alternative would freeze the entire existing corpus.
func sameBranch(row *model.FindingLineage, source *model.Source) bool {
	if row.GitBranch == "" || source == nil || source.GitBranch == "" {
		return true
	}
	return row.GitBranch == source.GitBranch
}

// userDecided reports whether a human, not a scanner, owns this row's status.
func userDecided(status model.LineageStatus) bool {
	switch status {
	case model.LineageStatusAcceptedRisk, model.LineageStatusFalsePositive, model.LineageStatusResolved:
		return true
	default:
		return false
	}
}

// checkableLLMRow reports whether a row can be verified against the code at
// all: LLM tier (a deterministic row does not use this path) and carrying the
// quote hash that lets the agent validate its cached quote.
func checkableLLMRow(row *model.FindingLineage) bool {
	return model.TierOf(row.Provenance) == model.TierLLM && row.QuoteHash != "" && row.MergedInto == ""
}

// syncMemory propagates a lineage transition to audit_memories (§8). Failure
// is logged, never fatal: a memory row that lags is a suppression bug on the
// next scan, whereas failing the closure pass would lose the transition
// entirely.
func (s *lineageService) syncMemory(row *model.FindingLineage, status model.LineageStatus) {
	if s.memory == nil {
		return
	}
	if err := s.memory.SetRemediationStatus(row.Fingerprint, model.MemoryStatusForLineage(status)); err != nil {
		log.Printf("[lineage] memory sync fingerprint=%s status=%s: %v", row.Fingerprint, status, err)
	}
}

func evidenceReason(check model.LineageCheck) string {
	if check.Reason != "" {
		return check.Reason
	}
	return check.Outcome
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// targetKeyed reports whether this scan groups lineage by target identity.
//
// False only when the identity could not be resolved — the bare container
// mount — because grouping every unattributed scan under one key would pool
// unrelated projects. That fallback is why the path-keyed reads and the
// source_path uniqueness constraint both stay live.
func targetKeyed(target TargetIdentity) bool {
	return target.Resolved()
}

// reanchorEnabled mirrors the 0076 switch that arms the line actuator.
func reanchorEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("VULTURE_LLM_QUOTE_REANCHOR")), "true")
}
