package repository

import "github.com/vulture/backend/internal/model"

// MockPipelineRepo implements PipelineRepository for testing.
type MockPipelineRepo struct {
	CreatePipelineFn       func(*model.Pipeline) error
	GetPipelineFn          func(string) (*model.Pipeline, error)
	UpdatePipelineFn       func(*model.Pipeline) error
	ListPipelinesFn        func(int, int) ([]model.Pipeline, error)
	GetPipelineByAuditIDFn func(string) (*model.Pipeline, error)
}

func (m *MockPipelineRepo) CreatePipeline(p *model.Pipeline) error {
	if m.CreatePipelineFn != nil {
		return m.CreatePipelineFn(p)
	}
	return nil
}

func (m *MockPipelineRepo) GetPipeline(id string) (*model.Pipeline, error) {
	if m.GetPipelineFn != nil {
		return m.GetPipelineFn(id)
	}
	return nil, nil
}

func (m *MockPipelineRepo) UpdatePipeline(p *model.Pipeline) error {
	if m.UpdatePipelineFn != nil {
		return m.UpdatePipelineFn(p)
	}
	return nil
}

func (m *MockPipelineRepo) ListPipelines(limit, offset int) ([]model.Pipeline, error) {
	if m.ListPipelinesFn != nil {
		return m.ListPipelinesFn(limit, offset)
	}
	return nil, nil
}

func (m *MockPipelineRepo) GetPipelineByAuditID(auditID string) (*model.Pipeline, error) {
	if m.GetPipelineByAuditIDFn != nil {
		return m.GetPipelineByAuditIDFn(auditID)
	}
	return nil, nil
}
