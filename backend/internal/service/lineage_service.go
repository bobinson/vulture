package service

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// MemoryStatusSync is the slice of the memory layer that lineage writes to.
// Feature 0091 §8: without it a finding the scanner closes stays "open" in
// audit_memories, so the next scan's prior-findings block still tells the
// model to skip it — the finding can never be re-reported and therefore never
// regress. An interface (not the whole MemoryService) so the dependency is one
// method wide and trivially mockable.
type MemoryStatusSync interface {
	SetRemediationStatus(fingerprint string, status string) error
}

// fixedRecheckAudits bounds the fixed-row re-check to the last N fixing audits
// of a target (feature 0091 §6.3, audit note P1).
const fixedRecheckAudits = 3

// LineageService tracks finding lifecycle across audit runs.
type LineageService interface {
	ProcessAuditFindings(audit *model.Audit, source *model.Source, findings []model.Finding) error
	// RecordScanOutcome is the per-(scan, agent) closure pass, and the ONLY
	// place an LLM-tier row may be closed. It reads every evidence outcome off
	// the result before it writes anything (feature 0091 §6.3).
	RecordScanOutcome(audit *model.Audit, source *model.Source, agentType string, result *model.ScanResult) error
	// PendingChecks builds the `lineage_checks_requested` block the backend
	// sends with the audit request, per agent type.
	PendingChecks(source *model.Source, agentTypes []string) map[string]*model.LineageChecksRequest
	UpdateStatus(lineageID string, update *model.LineageStatusUpdate) error
	GetLineage(id string) (*model.FindingLineage, error)
	// GetDetail is GET /api/lineage/{id}: the row, its timeline, and the two
	// blocks feature 0091 §10.1 adds — `evidence` (what the last scan actually
	// OBSERVED about the cited code) and `seen_in` (the audits that reported
	// this finding, matched by fingerprint_v2).
	GetDetail(id string) (*model.LineageDetail, error)
	GetLineageForFinding(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error)
	ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error)
	ListByAudit(auditID string) ([]model.FindingLineage, error)
	GetTimeline(lineageID string) ([]model.LineageEvent, error)
}

type lineageService struct {
	repo   repository.LineageRepository
	memory MemoryStatusSync
}

// NewLineageService creates a new lineage service with no memory sync. Status
// transitions are still recorded on the lineage row and its timeline; they
// simply do not reach audit_memories.
func NewLineageService(repo repository.LineageRepository) LineageService {
	return &lineageService{repo: repo}
}

// NewLineageServiceWithMemory wires the feature-0091 §8 memory sync, so a
// status the scanner sets is reflected in the prior-findings block the next
// scan shows the model.
func NewLineageServiceWithMemory(repo repository.LineageRepository, memory MemoryStatusSync) LineageService {
	return &lineageService{repo: repo, memory: memory}
}

func (s *lineageService) ProcessAuditFindings(audit *model.Audit, source *model.Source, findings []model.Finding) error {
	currentFingerprints := map[string]bool{}
	agentTypes := map[string]bool{}

	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		agentTypes[f.AgentType] = true
		// Feature 0079 A3, the dual-key bridge. Under VULTURE_FINDING_IDENTITY
		// =enforce, Fingerprint holds the NEW v2 value and LegacyFingerprint the
		// v1 one the stored rows are keyed on. Both are looked up and both count
		// as "currently present".
		//
		// Without this the first enforce run would find no match for any of the
		// 5,109 stored lineage rows, detectFixed would mark every one of them
		// FIXED, and createNewLineage would mint a fresh VLT ref for every
		// finding — a one-time destruction of human triage state
		// (accepted_risk, false_positive, notes, ticket_url).
		//
		// LegacyFingerprint is json:"-" and in no column list, so this bridge
		// lives entirely in memory and needs no backfill migration.
		for _, fp := range fingerprintsOf(f) {
			currentFingerprints[fp] = true
		}
	}

	// Read before write (§6.3, audit note R4): snapshot the rows each pass may
	// act on BEFORE the upserts below create or move any of them, so a row
	// minted by this very scan can never be considered for closure by it.
	target := ResolveTarget(source)
	snapshots := map[string][]model.FindingLineage{}
	if source != nil {
		for agentType := range agentTypes {
			snapshots[agentType] = s.rowsForPass(target, source, agentType, &model.ScanResult{})
		}
	}

	s.upsertFindings(audit, source, target, findings)

	// Close out what this scan did not report. The result payload is not
	// available on this path (it is the pre-0091 entry point, and the replay
	// and pipeline callers have only a finding list), so the pass runs with an
	// EMPTY ScanResult: `result_schema` 0, i.e. "scope unknown". That is the
	// conservative reading and it is the correct one — a caller that cannot
	// say what the scan looked at has not earned the right to close an
	// LLM-tier row on its silence (S26). Deterministic closure is unaffected.
	for agentType := range agentTypes {
		if err := s.closeForAgent(audit, source, target, agentType, &model.ScanResult{}, currentFingerprints, snapshots[agentType]); err != nil {
			log.Printf("[lineage] close pass error agent=%s: %v", agentType, err)
		}
	}
	return nil
}

// RecordScanOutcome is the feature-0091 entry point: it records the findings
// this agent DID report and then decides, per surviving lineage row, what the
// scan's silence about the rest actually means.
//
// The ordering matters and is required by the design (§6.3, audit note R4):
// every row the pass may act on is read BEFORE any write, so an upsert made
// halfway through cannot change which rows the closure loop then considers.
func (s *lineageService) RecordScanOutcome(audit *model.Audit, source *model.Source, agentType string, result *model.ScanResult) error {
	if source == nil {
		return nil
	}
	if result == nil {
		result = &model.ScanResult{}
	}
	target := ResolveTarget(source)
	rows := s.rowsForPass(target, source, agentType, result)
	agentFindings, present := findingsOfAgent(result.Findings, agentType)
	s.upsertFindings(audit, source, target, agentFindings)
	return s.closeForAgent(audit, source, target, agentType, result, present, rows)
}

// findingsOfAgent narrows a result's findings to one agent and returns, with
// them, the set of fingerprints that agent reported — the "present" set the
// closure pass tests every surviving lineage row against.
func findingsOfAgent(findings []model.Finding, agentType string) ([]model.Finding, map[string]bool) {
	out := make([]model.Finding, 0, len(findings))
	present := map[string]bool{}
	for _, f := range findings {
		if f.Fingerprint == "" || (f.AgentType != "" && f.AgentType != agentType) {
			continue
		}
		out = append(out, f)
		// Every identity the finding can be recognised by counts as present.
		// v1 alone was enough while lineage was path-keyed, because v1 and the
		// row's path moved together; under target identity a rescan of the
		// same tree under a new mount reports a NEW v1 for the SAME finding,
		// and matching on v1 alone would read that as "absent" and close it
		// (feature 0091 §7.3, S16).
		for _, fp := range identityKeysOf(f) {
			present[fp] = true
		}
	}
	return out, present
}

// closeForAgent runs one (audit, agent_type) closure pass.
func (s *lineageService) closeForAgent(audit *model.Audit, source *model.Source, target TargetIdentity,
	agentType string, result *model.ScanResult, present map[string]bool, rows []model.FindingLineage) error {
	pass := &scanPass{
		svc: s, audit: audit, source: source, agentType: agentType,
		present:    present,
		checks:     indexChecks(result.LineageChecks),
		scope:      newScanScope(result, target),
		llmEnabled: strings.TrimSpace(result.DegradedReason) == "",
		degraded:   strings.TrimSpace(result.DegradedReason),

		targetKeyed: targetKeyed(target),
		noResult:    result.NoResultSnapshot,
		shadowed:    result.RollupShadowed,
	}
	for i := range rows {
		pass.apply(&rows[i])
	}
	return nil
}

// rowsForPass returns every lineage row this pass may act on: the active rows
// for the (source, agent), plus the bounded set of recently-fixed LLM rows the
// scan is allowed to reconsider.
func (s *lineageService) rowsForPass(target TargetIdentity, source *model.Source, agentType string, result *model.ScanResult) []model.FindingLineage {
	rows, err := s.activeRows(target, source, agentType)
	if err != nil {
		log.Printf("[lineage] get active lineages agent=%s: %v", agentType, err)
		return nil
	}
	return append(rows, s.boundedFixedRows(target, source, agentType, result)...)
}

// activeRows reads the rows a scan may act on under whichever key is in force.
//
// VULTURE_LINEAGE_KEY=path is the documented one-release rollback and it is
// the ONLY thing this switch changes: the target key is still written on every
// row, so flipping back and forth loses nothing.
func (s *lineageService) activeRows(target TargetIdentity, source *model.Source, agentType string) ([]model.FindingLineage, error) {
	if !targetKeyed(target) {
		return s.repo.GetActiveBySourcePath(source.Path, agentType)
	}
	rows, err := s.repo.ActiveByTarget(target.Key, agentType)
	if err != nil {
		return nil, fmt.Errorf("active by target: %w", err)
	}
	legacy := s.legacyKey(source, target.Key)
	if legacy == "" {
		return rows, nil
	}
	extra, err := s.repo.ActiveByTarget(legacy, agentType)
	if err != nil {
		// The bridge is best-effort by design: losing it costs matches, and
		// failing the whole pass would cost the closures too.
		log.Printf("[lineage] legacy target read key=%s agent=%s: %v", legacy, agentType, err)
		return rows, nil
	}
	return mergeLineageRows(rows, extra), nil
}

// legacyKey returns the key migration 027's backfill would have attributed to
// this source path, or "" when there is nothing to bridge to (the backfilled
// key and the resolved one already agree, or the lookup failed).
//
// Feature 0091 §7 — see repository/lineage_legacy_key.go for why the two keys
// differ at all and why reading both is what stops the migration from
// orphaning every historical row's triage.
func (s *lineageService) legacyKey(source *model.Source, primary string) string {
	if source == nil || source.Path == "" {
		return ""
	}
	legacy, err := s.repo.LegacyTargetKey(source.Path)
	if err != nil {
		log.Printf("[lineage] legacy target key for %s: %v", source.Path, err)
		return ""
	}
	if legacy == primary {
		return ""
	}
	return legacy
}

// mergeLineageRows appends the rows of extra that base does not already hold.
//
// Dedup is by row id and it is required, not defensive: the two reads are the
// same query under two keys, and a row already re-keyed to the resolved key
// can still be returned by the legacy read on a store that has not converged.
// Applying one row twice in a pass would double-count seen_count and write two
// timeline entries for one observation.
func mergeLineageRows(base, extra []model.FindingLineage) []model.FindingLineage {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base))
	for i := range base {
		seen[base[i].ID] = true
	}
	for i := range extra {
		if !seen[extra[i].ID] {
			seen[extra[i].ID] = true
			base = append(base, extra[i])
		}
	}
	return base
}

// boundedFixedRows returns the `fixed` LLM rows worth re-checking this scan
// (S11). Only LLM rows, and only ones carrying a quote hash: a deterministic
// row that reappears is caught by the ordinary present-in-result path, and a
// row with no quote has nothing an agent could verify.
func (s *lineageService) boundedFixedRows(target TargetIdentity, source *model.Source,
	agentType string, result *model.ScanResult) []model.FindingLineage {
	if !result.HasEvidenceProtocol() {
		return nil
	}
	rows := s.recentlyFixedRows(target, source, agentType)
	out := make([]model.FindingLineage, 0, len(rows))
	for _, r := range rows {
		if checkableLLMRow(&r) {
			out = append(out, r)
		}
	}
	return out
}

// recentlyFixedRows reads the fixed window under whichever key is in force,
// through the SAME primary + legacy-bridge pattern activeRows uses.
//
// It has to: every other read moved to target identity and this one did not,
// so a row closed under one mount was invisible to a scan standing on another
// — and for a git source, where each ingest clones into a fresh directory,
// invisible from the very next scan onwards. The fallback path is the
// VULTURE_LINEAGE_KEY=path rollback, unchanged.
func (s *lineageService) recentlyFixedRows(target TargetIdentity, source *model.Source,
	agentType string) []model.FindingLineage {
	if !targetKeyed(target) {
		rows, err := s.repo.GetRecentlyFixedBySourcePath(source.Path, agentType, fixedRecheckAudits)
		if err != nil {
			log.Printf("[lineage] recently fixed lookup agent=%s: %v", agentType, err)
			return nil
		}
		return rows
	}
	rows, err := s.repo.RecentlyFixedByTarget(target.Key, agentType, fixedRecheckAudits)
	if err != nil {
		log.Printf("[lineage] recently fixed by target key=%s agent=%s: %v", target.Key, agentType, err)
		return nil
	}
	legacy := s.legacyKey(source, target.Key)
	if legacy == "" {
		return rows
	}
	extra, err := s.repo.RecentlyFixedByTarget(legacy, agentType, fixedRecheckAudits)
	if err != nil {
		// Best-effort, exactly as in activeRows: losing the bridge costs
		// matches, and failing the whole pass would cost the checks too.
		log.Printf("[lineage] legacy recently-fixed read key=%s agent=%s: %v", legacy, agentType, err)
		return rows
	}
	return mergeLineageRows(rows, extra)
}

// PendingChecks builds the `lineage_checks_requested` block per agent type.
func (s *lineageService) PendingChecks(source *model.Source, agentTypes []string) map[string]*model.LineageChecksRequest {
	if source == nil || len(agentTypes) == 0 {
		return nil
	}
	target := ResolveTarget(source)
	out := map[string]*model.LineageChecksRequest{}
	for _, at := range agentTypes {
		rows := s.checkableRows(target, source, at)
		if len(rows) == 0 {
			continue
		}
		out[at] = &model.LineageChecksRequest{Schema: model.LineageChecksRequestSchema, Rows: rows}
	}
	return out
}

// checkableRows collects the request rows for one agent type: active LLM rows
// plus the bounded fixed set, all in-branch and all carrying a quote hash.
func (s *lineageService) checkableRows(target TargetIdentity, source *model.Source, agentType string) []model.LineageCheckRequest {
	// An evidence-capable result is assumed here: the request is what ASKS the
	// agent for evidence, so refusing to ask an agent that has not yet
	// answered would make the protocol unreachable.
	evidenceReady := &model.ScanResult{ResultSchema: model.ScanResultSchemaEvidence}
	rows := s.rowsForPass(target, source, agentType, evidenceReady)
	out := make([]model.LineageCheckRequest, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		if !checkableLLMRow(row) || !sameBranch(row, source) || userDecided(row.CurrentStatus) {
			continue
		}
		out = append(out, model.LineageCheckRequest{
			LineageID:     row.ID,
			FingerprintV2: firstNonEmpty(row.FingerprintV2, row.Fingerprint),
			RelPath:       row.FilePath,
			LineStart:     row.EvidenceLineStart,
			LineEnd:       row.EvidenceLineEnd,
			QuoteHash:     row.QuoteHash,
			Status:        string(row.CurrentStatus),
			FileHash:      row.EvidenceFileHash,
		})
	}
	return out
}

// upsertFindings records every finding this scan reported: a new lineage row
// for one that has never been seen, an in-place update (and a regression, when
// the row was closed) for one that has.
func (s *lineageService) upsertFindings(audit *model.Audit, source *model.Source, target TargetIdentity, findings []model.Finding) {
	if source == nil || len(findings) == 0 {
		return
	}
	now := time.Now().UTC()
	existingMap := s.lookupExisting(findings, target, source)
	for i := range findings {
		f := findings[i]
		if f.Fingerprint == "" {
			continue
		}
		if existing := resolveExisting(existingMap, &f); existing != nil {
			if err := s.updateExistingLineage(existing, audit, source, target, &f, now); err != nil {
				log.Printf("[lineage] update error id=%s: %v", existing.ID, err)
			}
			continue
		}
		if err := s.createNewLineage(audit, source, target, &f, now); err != nil {
			log.Printf("[lineage] create error: %v", err)
		}
	}
}

// lookupExisting batch-fetches the lineage rows these findings may already own.
//
// Under target identity the lookup is keyed by target and matches on EITHER
// identity (§7.3). Getting this wrong is not a missed optimisation: an
// unmatched finding takes the createNewLineage branch, which mints a second
// row with a second VLT ref and a fresh first-seen date, and orphans whatever
// a human had decided about the first one.
func (s *lineageService) lookupExisting(findings []model.Finding, target TargetIdentity, source *model.Source) map[string]*model.FindingLineage {
	sourcePath := ""
	if source != nil {
		sourcePath = source.Path
	}
	if targetKeyed(target) {
		return s.lookupByTarget(findings, target, source)
	}
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Fingerprint != "" {
			fps = append(fps, fingerprintsOf(f)...)
		}
	}
	return s.logLookup(s.repo.GetLineageByFingerprints(fps, sourcePath))
}

// lookupByTarget is the target-keyed half of lookupExisting, consulting the
// resolved key and — when they differ — the key migration 027's backfill wrote.
//
// The bridge is not an optimisation. A row the backfill keyed `path:<segment>`
// is invisible to the resolved `git:`/`marker:` key, and an unmatched finding
// takes the CREATE branch: a second VLT ref, a fresh first-seen date, and the
// accepted_risk / false_positive / notes / ticket on the first row orphaned.
// Matching through the legacy key also RE-KEYS the row (updateExistingLineage
// writes target.Key), so the bridge empties itself as a target is rescanned.
func (s *lineageService) lookupByTarget(findings []model.Finding, target TargetIdentity,
	source *model.Source) map[string]*model.FindingLineage {
	keys := identityKeysOfAll(findings)
	found := s.logLookup(s.repo.GetLineageByFingerprintsForTarget(keys, target.Key))
	legacy := s.legacyKey(source, target.Key)
	if legacy == "" {
		return found
	}
	return mergeLineageIndex(found, s.logLookup(s.repo.GetLineageByFingerprintsForTarget(keys, legacy)))
}

// mergeLineageIndex folds the legacy-key lookup into the primary one. The
// PRIMARY wins every collision: it is the key the row will be written under,
// so preferring it keeps a converged row from being resolved through the
// bridge it has already left.
func mergeLineageIndex(primary, legacy map[string]*model.FindingLineage) map[string]*model.FindingLineage {
	if len(legacy) == 0 {
		return primary
	}
	if primary == nil {
		primary = map[string]*model.FindingLineage{}
	}
	for k, v := range legacy {
		if _, ok := primary[k]; !ok {
			primary[k] = v
		}
	}
	return primary
}

// logLookup keeps the two lookup branches to one error-handling policy: a
// failed batch read degrades to "nothing matched", which is the same shape the
// pre-0091 code had.
func (s *lineageService) logLookup(m map[string]*model.FindingLineage, err error) map[string]*model.FindingLineage {
	if err != nil {
		log.Printf("[lineage] batch lookup error: %v", err)
		return nil
	}
	return m
}

// resolveExisting finds the row a finding already owns, under either identity.
//
// The v1 fallback is the 0079 dual-key bridge and it is load-bearing: without
// it the first run under the new identity would match NO stored row, mark
// every one of them fixed, and mint a fresh VLT ref for every finding — a
// one-time destruction of human triage state.
func resolveExisting(existingMap map[string]*model.FindingLineage, f *model.Finding) *model.FindingLineage {
	// fingerprint_v2 FIRST: it is the identity that survives a mount change,
	// so under target identity it is the one that recognises the row. v1 stays
	// the fallback (and the stable ref id) for every row that has no v2.
	for _, key := range identityKeysOf(*f) {
		if existing := existingMap[key+"|"+f.AgentType]; existing != nil {
			return existing
		}
	}
	return nil
}

func (s *lineageService) createNewLineage(audit *model.Audit, source *model.Source, target TargetIdentity, f *model.Finding, now time.Time) error {
	l := &model.FindingLineage{
		Fingerprint:   f.Fingerprint,
		SourcePath:    source.Path,
		AgentType:     f.AgentType,
		CurrentStatus: model.LineageStatusOpen,
		FirstAuditID:  audit.ID,
		FirstFoundAt:  now,
		LatestAuditID: audit.ID,
		LatestFoundAt: &now,
		Severity:      string(f.Severity),
		Category:      f.Category,
		Title:         f.Title,
		FilePath:      f.FilePath,
		FirstCommit:   source.GitCommitShort,
		LatestCommit:  source.GitCommitShort,
		// Feature 0091. Provenance decides the row's tier and therefore which
		// closure rule it obeys; the quote hash is what makes it checkable at
		// all; the claimed window is what the agent verifies AROUND. Recording
		// them at creation is what lets the very next scan carry the row
		// forward instead of reading the model's silence as repair.
		Provenance:        f.Provenance,
		QuoteHash:         f.QuoteHash,
		FingerprintV2:     f.FingerprintV2,
		GitBranch:         source.GitBranch,
		EvidenceLineStart: f.LineStart,
		EvidenceLineEnd:   f.LineEnd,
		SeenCount:         1,
		LastSeenAuditID:   audit.ID,
		// Written even under VULTURE_LINEAGE_KEY=path: the rollback changes
		// which key is READ, never which is recorded, so flipping back to
		// target mode does not need a second backfill.
		TargetKey: target.Key,
	}
	if err := s.repo.UpsertLineage(l); err != nil {
		return fmt.Errorf("create lineage: %w", err)
	}
	return s.repo.AddEvent(&model.LineageEvent{
		LineageID: l.ID,
		EventType: model.LineageEventDetected,
		AuditID:   audit.ID,
		NewStatus: string(model.LineageStatusOpen),
		GitCommit: source.GitCommitShort,
		GitBranch: source.GitBranch,
	})
}

func (s *lineageService) updateExistingLineage(existing *model.FindingLineage, audit *model.Audit, source *model.Source, target TargetIdentity, f *model.Finding, now time.Time) error {
	existing.LatestAuditID = audit.ID
	existing.LatestFoundAt = &now
	existing.LatestCommit = source.GitCommitShort
	// Feature 0091: refresh the identity/evidence metadata from the finding as
	// reported THIS scan. A row created before the agent emitted a quote hash
	// (or before provenance existed at all) acquires one here rather than
	// staying permanently unconfirmable. Empty values do not overwrite —
	// losing a quote hash to an agent that stopped sending one would silently
	// downgrade the row.
	existing.Provenance = firstNonEmpty(f.Provenance, existing.Provenance)
	existing.QuoteHash = firstNonEmpty(f.QuoteHash, existing.QuoteHash)
	existing.FingerprintV2 = firstNonEmpty(f.FingerprintV2, existing.FingerprintV2)
	existing.GitBranch = firstNonEmpty(source.GitBranch, existing.GitBranch)
	existing.TargetKey = firstNonEmpty(target.Key, existing.TargetKey)
	// Feature 0091 §6.5. `file_path` is otherwise frozen in the coordinates of
	// the scan that first raised the finding, and the scope check can only
	// place a path that is relative or under THIS scan's root. Once target
	// identity lets a native scan see a row a docker run recorded at
	// /mnt/source/..., a frozen path is unplaceable on every later scan: the
	// row is reported out_of_scope forever and a genuine repair can never
	// close it. Adopting the path from the scan that just RE-FOUND the finding
	// puts the row back in coordinates the next scan can resolve.
	//
	// Only on a sighting, and never to empty: a scan that did not report the
	// finding has no path to offer, and this is the one place a path is known
	// to be current because the agent just read that file.
	existing.FilePath = firstNonEmpty(f.FilePath, existing.FilePath)
	if f.LineStart > 0 {
		existing.EvidenceLineStart = f.LineStart
		existing.EvidenceLineEnd = f.LineEnd
	}
	if err := s.repo.UpsertLineage(existing); err != nil {
		return fmt.Errorf("update lineage: %w", err)
	}

	// Regression: was fixed, now reappeared
	if existing.CurrentStatus == model.LineageStatusFixed {
		if err := s.repo.MarkRegression(existing.ID, audit.ID, ""); err != nil {
			return fmt.Errorf("mark regression: %w", err)
		}
		return s.repo.AddEvent(&model.LineageEvent{
			LineageID: existing.ID,
			EventType: model.LineageEventRegression,
			AuditID:   audit.ID,
			OldStatus: string(model.LineageStatusFixed),
			NewStatus: string(model.LineageStatusRegression),
			GitCommit: source.GitCommitShort,
			GitBranch: source.GitBranch,
		})
	}
	return nil
}

func (s *lineageService) UpdateStatus(lineageID string, update *model.LineageStatusUpdate) error {
	existing, err := s.repo.GetLineage(lineageID)
	if err != nil {
		return fmt.Errorf("get lineage: %w", err)
	}
	if existing == nil {
		return ErrNotFound
	}

	oldStatus := string(existing.CurrentStatus)
	if err := s.repo.UpdateStatus(lineageID, update.Status, update.Notes, update.TicketURL); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	_ = s.repo.AddEvent(&model.LineageEvent{
		LineageID: lineageID,
		EventType: model.LineageEventStatusChange,
		OldStatus: oldStatus,
		NewStatus: update.Status,
	})

	if update.Notes != "" {
		_ = s.repo.AddEvent(&model.LineageEvent{
			LineageID: lineageID,
			EventType: model.LineageEventNoteAdded,
			Notes:     update.Notes,
		})
	}
	return nil
}

func (s *lineageService) GetLineage(id string) (*model.FindingLineage, error) {
	l, err := s.repo.GetLineage(id)
	if err != nil {
		return nil, fmt.Errorf("get lineage: %w", err)
	}
	if l == nil {
		return nil, ErrNotFound
	}
	return l, nil
}

// GetDetail assembles the extended detail payload. The pre-0091 `lineage` and
// `events` keys are untouched: this endpoint is EXTENDED, not replaced, and
// the /audit/{id} deep links already read those two.
func (s *lineageService) GetDetail(id string) (*model.LineageDetail, error) {
	lineage, err := s.GetLineage(id)
	if err != nil {
		return nil, err
	}
	events, err := s.repo.GetEvents(id)
	if err != nil {
		return nil, fmt.Errorf("get lineage events: %w", err)
	}
	if events == nil {
		events = []model.LineageEvent{}
	}
	// The ONE read in this feature that touches `findings`, and it is bounded
	// to this row. The aggregate is forbidden the same join because a whole
	// report's worth of it is what makes the report unusable (§10.1).
	seenIn, err := s.repo.SeenInAudits(lineage)
	if err != nil {
		return nil, fmt.Errorf("get seen-in audits: %w", err)
	}
	return &model.LineageDetail{
		Lineage:  lineage,
		Events:   events,
		Evidence: evidenceBlockOf(lineage, events),
		SeenIn:   seenIn,
	}, nil
}

// evidenceBlockOf reports what the last scan OBSERVED about the cited code.
//
// It is the difference between "nobody mentioned it" and "a scan re-read the
// file and the quote is still there" — the distinction the whole feature turns
// on, and one that is invisible from `current_status` alone. The window and
// the file hash come from the row (ApplyEvidence wrote them); the outcome and
// its reason come from the last EVIDENCE event, because only the event records
// why.
//
// nil when nothing was ever observed: a row from before 0091 has no evidence
// to show, and an empty block would read as an observation that came back
// blank.
func evidenceBlockOf(l *model.FindingLineage, events []model.LineageEvent) *model.LineageEvidence {
	ev := &model.LineageEvidence{
		LineStart: l.EvidenceLineStart,
		LineEnd:   l.EvidenceLineEnd,
		FileHash:  l.EvidenceFileHash,
		CheckedAt: l.UpdatedAt,
	}
	if last := lastEvidenceEvent(events); last != nil {
		ev.LastOutcome = model.EvidenceOutcomes[last.EventType]
		ev.Reason = last.Notes
		ev.CheckedAt = last.CreatedAt
	}
	if ev.LastOutcome == "" && ev.FileHash == "" && ev.LineStart == 0 {
		return nil
	}
	return ev
}

// lastEvidenceEvent is the most recent event that is an evidence observation.
// `detected`, `status_change` and `note_added` are not observations and are
// skipped, so a human note added after a confirmation cannot displace it.
func lastEvidenceEvent(events []model.LineageEvent) *model.LineageEvent {
	var last *model.LineageEvent
	for i := range events {
		if _, ok := model.EvidenceOutcomes[events[i].EventType]; !ok {
			continue
		}
		if last == nil || !events[i].CreatedAt.Before(last.CreatedAt) {
			last = &events[i]
		}
	}
	return last
}

func (s *lineageService) GetLineageForFinding(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	l, err := s.repo.GetLineageByFingerprint(fingerprint, sourcePath, agentType)
	if err != nil {
		return nil, fmt.Errorf("get lineage by fingerprint: %w", err)
	}
	if l == nil {
		return nil, ErrNotFound
	}
	return l, nil
}

func (s *lineageService) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
	return s.repo.ListBySourcePath(sourcePath, status, limit, offset)
}

func (s *lineageService) ListByAudit(auditID string) ([]model.FindingLineage, error) {
	return s.repo.ListByAudit(auditID)
}

func (s *lineageService) GetTimeline(lineageID string) ([]model.LineageEvent, error) {
	return s.repo.GetEvents(lineageID)
}

// identityKeysOf returns every identity a finding can be RECOGNISED by, most
// specific first: fingerprint_v2 (feature 0079, path-canonical and therefore
// stable across mounts), then the v1 fingerprint, then the pre-flip legacy
// one. Duplicates and blanks are dropped.
//
// Distinct from fingerprintsOf, which answers the narrower pre-0091 question
// "under which v1 identities may this row be STORED". Widening that function
// in place would have changed the path-keyed rollback's behaviour too.
func identityKeysOf(f model.Finding) []string {
	out := make([]string, 0, 3)
	for _, k := range []string{f.FingerprintV2, f.Fingerprint, f.LegacyFingerprint} {
		if k == "" || containsString(out, k) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// identityKeysOfAll flattens identityKeysOf over a batch, for the one
// target-scoped lookup query.
func identityKeysOfAll(findings []model.Finding) []string {
	out := make([]string, 0, 2*len(findings))
	seen := make(map[string]bool, 2*len(findings))
	for _, f := range findings {
		for _, k := range identityKeysOf(f) {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// fingerprintsOf returns every identity a finding may be stored under: its
// current fingerprint, plus the pre-0079 one when the A3 identity flip is
// active. Feature 0079 A3.
func fingerprintsOf(f model.Finding) []string {
	if f.LegacyFingerprint == "" || f.LegacyFingerprint == f.Fingerprint {
		return []string{f.Fingerprint}
	}
	return []string{f.Fingerprint, f.LegacyFingerprint}
}
