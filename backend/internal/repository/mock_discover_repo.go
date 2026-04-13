package repository

import "github.com/vulture/backend/internal/model"

// MockDiscoverRepo implements DiscoverRepository for testing.
type MockDiscoverRepo struct {
	SaveDiscoverResultFn        func(*model.DiscoverResult) error
	GetDiscoverResultFn         func(string) (*model.DiscoverResult, error)
	GetDiscoverResultByAuditIDFn func(string) (*model.DiscoverResult, error)
	GetDiscoverResultByTargetFn func(string) (*model.DiscoverResult, error)
}

func (m *MockDiscoverRepo) SaveDiscoverResult(dr *model.DiscoverResult) error {
	if m.SaveDiscoverResultFn != nil {
		return m.SaveDiscoverResultFn(dr)
	}
	return nil
}

func (m *MockDiscoverRepo) GetDiscoverResult(id string) (*model.DiscoverResult, error) {
	if m.GetDiscoverResultFn != nil {
		return m.GetDiscoverResultFn(id)
	}
	return nil, nil
}

func (m *MockDiscoverRepo) GetDiscoverResultByAuditID(auditID string) (*model.DiscoverResult, error) {
	if m.GetDiscoverResultByAuditIDFn != nil {
		return m.GetDiscoverResultByAuditIDFn(auditID)
	}
	return nil, nil
}

func (m *MockDiscoverRepo) GetDiscoverResultByTarget(targetURL string) (*model.DiscoverResult, error) {
	if m.GetDiscoverResultByTargetFn != nil {
		return m.GetDiscoverResultByTargetFn(targetURL)
	}
	return nil, nil
}
