package repository

import "github.com/vulture/backend/internal/model"

// MockLineageRepository implements LineageRepository for testing.
type MockLineageRepository struct {
	UpsertLineageFn          func(*model.FindingLineage) error
	GetLineageFn             func(string) (*model.FindingLineage, error)
	GetLineageByFingerprintFn func(string, string, string) (*model.FindingLineage, error)
	ListBySourcePathFn       func(string, string, int, int) ([]model.FindingLineage, error)
	ListByAuditFn            func(string) ([]model.FindingLineage, error)
	UpdateStatusFn           func(string, string, string, string) error
	MarkFixedFn              func(string, string, string) error
	MarkRegressionFn         func(string, string, string) error
	GetOpenBySourcePathFn    func(string, string) ([]model.FindingLineage, error)
	AddEventFn               func(*model.LineageEvent) error
	GetEventsFn              func(string) ([]model.LineageEvent, error)
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

func (m *MockLineageRepository) GetOpenBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error) {
	if m.GetOpenBySourcePathFn != nil {
		return m.GetOpenBySourcePathFn(sourcePath, agentType)
	}
	return nil, nil
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
