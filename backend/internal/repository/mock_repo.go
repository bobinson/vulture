package repository

import "github.com/vulture/backend/internal/model"

// MockAuditRepository implements AuditRepository for testing.
type MockAuditRepository struct {
	CreateSourceFn            func(*model.Source) error
	GetSourceFn               func(string) (*model.Source, error)
	FindSourceByPathFn        func(string) (*model.Source, error)
	UpdateSourceGitInfoFn     func(string, string, string, string, string) error
	CreateAuditFn             func(*model.Audit) error
	GetAuditFn                func(string) (*model.Audit, error)
	UpdateAuditFn             func(*model.Audit) error
	SaveFindingsFn            func(string, []model.Finding) error
	ListAuditsFn              func(int, int) ([]model.Audit, error)
	GetStatsFn                func() (*model.DashboardStats, error)
	GetLatestCompletedAuditFn     func(string, []string) (*model.Audit, error)
	GetPreviousCompletedAuditFn   func(string, []string, string) (*model.Audit, error)
	ListAuditsBySourcePathFn      func(string, int, int) ([]model.Audit, error)
}

func (m *MockAuditRepository) CreateSource(src *model.Source) error {
	if m.CreateSourceFn != nil {
		return m.CreateSourceFn(src)
	}
	return nil
}

func (m *MockAuditRepository) GetSource(id string) (*model.Source, error) {
	if m.GetSourceFn != nil {
		return m.GetSourceFn(id)
	}
	return nil, nil
}

func (m *MockAuditRepository) FindSourceByPath(path string) (*model.Source, error) {
	if m.FindSourceByPathFn != nil {
		return m.FindSourceByPathFn(path)
	}
	return nil, nil
}

func (m *MockAuditRepository) UpdateSourceGitInfo(id, branch, commitHash, commitShort, remoteURL string) error {
	if m.UpdateSourceGitInfoFn != nil {
		return m.UpdateSourceGitInfoFn(id, branch, commitHash, commitShort, remoteURL)
	}
	return nil
}

func (m *MockAuditRepository) CreateAudit(audit *model.Audit) error {
	if m.CreateAuditFn != nil {
		return m.CreateAuditFn(audit)
	}
	return nil
}

func (m *MockAuditRepository) GetAudit(id string) (*model.Audit, error) {
	if m.GetAuditFn != nil {
		return m.GetAuditFn(id)
	}
	return nil, nil
}

func (m *MockAuditRepository) UpdateAudit(audit *model.Audit) error {
	if m.UpdateAuditFn != nil {
		return m.UpdateAuditFn(audit)
	}
	return nil
}

func (m *MockAuditRepository) SaveFindings(auditID string, findings []model.Finding) error {
	if m.SaveFindingsFn != nil {
		return m.SaveFindingsFn(auditID, findings)
	}
	return nil
}

func (m *MockAuditRepository) ListAudits(limit, offset int) ([]model.Audit, error) {
	if m.ListAuditsFn != nil {
		return m.ListAuditsFn(limit, offset)
	}
	return nil, nil
}

func (m *MockAuditRepository) GetStats() (*model.DashboardStats, error) {
	if m.GetStatsFn != nil {
		return m.GetStatsFn()
	}
	return nil, nil
}

func (m *MockAuditRepository) GetLatestCompletedAudit(sourceID string, types []string) (*model.Audit, error) {
	if m.GetLatestCompletedAuditFn != nil {
		return m.GetLatestCompletedAuditFn(sourceID, types)
	}
	return nil, nil
}

func (m *MockAuditRepository) GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error) {
	if m.GetPreviousCompletedAuditFn != nil {
		return m.GetPreviousCompletedAuditFn(sourceID, types, excludeAuditID)
	}
	return nil, nil
}

func (m *MockAuditRepository) ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error) {
	if m.ListAuditsBySourcePathFn != nil {
		return m.ListAuditsBySourcePathFn(sourcePath, limit, offset)
	}
	return nil, nil
}
