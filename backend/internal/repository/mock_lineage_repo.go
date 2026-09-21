package repository

import "github.com/vulture/backend/internal/model"

// MockLineageRepository implements LineageRepository for testing.
type MockLineageRepository struct {
	UpsertLineageFn            func(*model.FindingLineage) error
	GetLineageFn               func(string) (*model.FindingLineage, error)
	GetLineageByFingerprintFn  func(string, string, string) (*model.FindingLineage, error)
	GetLineageByFingerprintsFn func([]string, string) (map[string]*model.FindingLineage, error)
	ListBySourcePathFn         func(string, string, int, int) ([]model.FindingLineage, error)
	ListByAuditFn              func(string) ([]model.FindingLineage, error)
	UpdateStatusFn             func(string, string, string, string) error
	MarkFixedFn                func(string, string, string) error
	MarkRegressionFn           func(string, string, string) error
	GetActiveBySourcePathFn    func(string, string) ([]model.FindingLineage, error)
	AddEventFn                 func(*model.LineageEvent) error
	GetEventsFn                func(string) ([]model.LineageEvent, error)
	// Feature 0091, following the same per-method Fn pattern.
	GetRecentlyFixedBySourcePathFn func(string, string, int) ([]model.FindingLineage, error)
	MarkUnconfirmedFn              func(string, string) error
	MarkSeenFn                     func(string, string) error
	ApplyEvidenceFn                func(string, LineageEvidenceUpdate) error
	// Feature 0091 P3 (target identity). ActiveByTargetFn defaults to the
	// path-keyed stub so a test written before P3 keeps working: it asked
	// "which rows may this scan act on", and under the target key that is the
	// same question with a different argument.
	ActiveByTargetFn                    func(string, string) ([]model.FindingLineage, error)
	RecentlyFixedByTargetFn             func(string, string, int) ([]model.FindingLineage, error)
	GetLineageByFingerprintsForTargetFn func([]string, string) (map[string]*model.FindingLineage, error)
	LegacyTargetKeyFn                   func(string) (string, error)
	LegacyTargetKeysForFn               func(string) ([]string, error)
	// Feature 0091 P4 (the target-scoped read side).
	ListTargetsFn       func() ([]model.TargetSummary, error)
	TargetScansFn       func(string) ([]model.TargetScan, error)
	AggregateByTargetFn func(model.AggregateQuery) (*model.AggregateReport, error)
	CountTargetScansFn  func(string, []string) (int, error)
	SeenInAuditsFn      func(*model.FindingLineage) ([]string, error)
}

func (m *MockLineageRepository) UpsertLineage(l *model.FindingLineage) error {
	if m.UpsertLineageFn != nil {
		return m.UpsertLineageFn(l)
	}
	return nil
}

func (m *MockLineageRepository) GetLineage(id string) (*model.FindingLineage, error) {
	if m.GetLineageFn != nil {
		return m.GetLineageFn(id)
	}
	return nil, nil
}

func (m *MockLineageRepository) GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error) {
	if m.GetLineageByFingerprintFn != nil {
		return m.GetLineageByFingerprintFn(fingerprint, sourcePath, agentType)
	}
	return nil, nil
}

func (m *MockLineageRepository) GetLineageByFingerprints(fingerprints []string, sourcePath string) (map[string]*model.FindingLineage, error) {
	if m.GetLineageByFingerprintsFn != nil {
		return m.GetLineageByFingerprintsFn(fingerprints, sourcePath)
	}
	return nil, nil
}

func (m *MockLineageRepository) ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error) {
	if m.ListBySourcePathFn != nil {
		return m.ListBySourcePathFn(sourcePath, status, limit, offset)
	}
	return nil, nil
}

func (m *MockLineageRepository) ListByAudit(auditID string) ([]model.FindingLineage, error) {
	if m.ListByAuditFn != nil {
		return m.ListByAuditFn(auditID)
	}
	return nil, nil
}

func (m *MockLineageRepository) UpdateStatus(id string, status string, notes string, ticketURL string) error {
	if m.UpdateStatusFn != nil {
		return m.UpdateStatusFn(id, status, notes, ticketURL)
	}
	return nil
}

func (m *MockLineageRepository) MarkFixed(id, auditID, commit string) error {
	if m.MarkFixedFn != nil {
		return m.MarkFixedFn(id, auditID, commit)
	}
	return nil
}

func (m *MockLineageRepository) MarkRegression(id, auditID, commit string) error {
	if m.MarkRegressionFn != nil {
		return m.MarkRegressionFn(id, auditID, commit)
	}
	return nil
}

func (m *MockLineageRepository) GetActiveBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error) {
	if m.GetActiveBySourcePathFn != nil {
		return m.GetActiveBySourcePathFn(sourcePath, agentType)
	}
	return nil, nil
}

func (m *MockLineageRepository) ActiveByTarget(targetKey, agentType string) ([]model.FindingLineage, error) {
	if m.ActiveByTargetFn != nil {
		return m.ActiveByTargetFn(targetKey, agentType)
	}
	// Fall through to the path-keyed stub. A pre-P3 test sets only
	// GetActiveBySourcePathFn, and its subject now reads by target; without
	// this the rows would silently vanish and the test would pass for the
	// wrong reason.
	return m.GetActiveBySourcePath(targetKey, agentType)
}

func (m *MockLineageRepository) GetLineageByFingerprintsForTarget(fingerprints []string, targetKey string) (map[string]*model.FindingLineage, error) {
	if m.GetLineageByFingerprintsForTargetFn != nil {
		return m.GetLineageByFingerprintsForTargetFn(fingerprints, targetKey)
	}
	return m.GetLineageByFingerprints(fingerprints, targetKey)
}

// LegacyTargetKey defaults to "" — no bridge — so a test that says nothing
// about the backfill gets exactly the primary-key behaviour it wrote.
func (m *MockLineageRepository) LegacyTargetKey(sourcePath string) (string, error) {
	if m.LegacyTargetKeyFn != nil {
		return m.LegacyTargetKeyFn(sourcePath)
	}
	return "", nil
}

func (m *MockLineageRepository) AddEvent(e *model.LineageEvent) error {
	if m.AddEventFn != nil {
		return m.AddEventFn(e)
	}
	return nil
}

func (m *MockLineageRepository) GetEvents(lineageID string) ([]model.LineageEvent, error) {
	if m.GetEventsFn != nil {
		return m.GetEventsFn(lineageID)
	}
	return nil, nil
}

func (m *MockLineageRepository) GetRecentlyFixedBySourcePath(sourcePath, agentType string, auditWindow int) ([]model.FindingLineage, error) {
	if m.GetRecentlyFixedBySourcePathFn != nil {
		return m.GetRecentlyFixedBySourcePathFn(sourcePath, agentType, auditWindow)
	}
	return nil, nil
}

// RecentlyFixedByTarget defaults to the path-keyed stub for the same reason
// ActiveByTarget does: a test written before the read moved to target identity
// set only GetRecentlyFixedBySourcePathFn, and its subject now asks the same
// question with a different argument.
func (m *MockLineageRepository) RecentlyFixedByTarget(targetKey, agentType string, auditWindow int) ([]model.FindingLineage, error) {
	if m.RecentlyFixedByTargetFn != nil {
		return m.RecentlyFixedByTargetFn(targetKey, agentType, auditWindow)
	}
	return m.GetRecentlyFixedBySourcePath(targetKey, agentType, auditWindow)
}

func (m *MockLineageRepository) MarkUnconfirmed(id, auditID string) error {
	if m.MarkUnconfirmedFn != nil {
		return m.MarkUnconfirmedFn(id, auditID)
	}
	return nil
}

func (m *MockLineageRepository) MarkSeen(id, auditID string) error {
	if m.MarkSeenFn != nil {
		return m.MarkSeenFn(id, auditID)
	}
	return nil
}

func (m *MockLineageRepository) ApplyEvidence(id string, ev LineageEvidenceUpdate) error {
	if m.ApplyEvidenceFn != nil {
		return m.ApplyEvidenceFn(id, ev)
	}
	return nil
}

// ── Feature 0091 P4: the target-scoped read side ────────────────────────────
// Each defaults to an empty answer, so a test that says nothing about the
// aggregate gets an empty report rather than a nil-map panic.

func (m *MockLineageRepository) ListTargets() ([]model.TargetSummary, error) {
	if m.ListTargetsFn != nil {
		return m.ListTargetsFn()
	}
	return nil, nil
}

func (m *MockLineageRepository) TargetScans(targetKey string) ([]model.TargetScan, error) {
	if m.TargetScansFn != nil {
		return m.TargetScansFn(targetKey)
	}
	return nil, nil
}

func (m *MockLineageRepository) AggregateByTarget(q model.AggregateQuery) (*model.AggregateReport, error) {
	if m.AggregateByTargetFn != nil {
		return m.AggregateByTargetFn(q)
	}
	return &model.AggregateReport{Page: q.Page, PageSize: q.PageSize, Rows: []model.AggregateRow{}}, nil
}

func (m *MockLineageRepository) CountTargetScans(targetKey string, scans []string) (int, error) {
	if m.CountTargetScansFn != nil {
		return m.CountTargetScansFn(targetKey, scans)
	}
	return len(scans), nil
}

func (m *MockLineageRepository) SeenInAudits(l *model.FindingLineage) ([]string, error) {
	if m.SeenInAuditsFn != nil {
		return m.SeenInAuditsFn(l)
	}
	return []string{}, nil
}
