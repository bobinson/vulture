package repository

import "github.com/vulture/backend/internal/model"

// MockMemoryRepository implements MemoryRepository for testing.
type MockMemoryRepository struct {
	StoreMemoryFn        func(*model.AuditMemory) error
	StoreEmbeddingFn     func(string, []float32) error
	SearchMemoriesFn     func(string, []float32, int) ([]model.AuditMemory, error)
	FindSimilarByVectorFn func(string, []float32, int) ([]model.AuditMemory, error)
	GetMemoryFn          func(string) (*model.AuditMemory, error)
	UpdateRemediationFn  func(string, string, string) error
	ListMemoriesByAuditFn func(string) ([]model.AuditMemory, error)
	ListByCodebasePathFn func(string, string, int) ([]model.AuditMemory, error)
	ListRecentFn         func(int) ([]model.AuditMemory, error)
	StoreEdgeFn          func(*model.MemoryEdge) error
	GetEdgesFn           func(string) ([]model.MemoryEdge, error)
}

func (m *MockMemoryRepository) StoreMemory(mem *model.AuditMemory) error {
	if m.StoreMemoryFn != nil {
		return m.StoreMemoryFn(mem)
	}
	return nil
}

func (m *MockMemoryRepository) StoreEmbedding(id string, embedding []float32) error {
	if m.StoreEmbeddingFn != nil {
		return m.StoreEmbeddingFn(id, embedding)
	}
	return nil
}

func (m *MockMemoryRepository) SearchMemories(query string, embedding []float32, limit int) ([]model.AuditMemory, error) {
	if m.SearchMemoriesFn != nil {
		return m.SearchMemoriesFn(query, embedding, limit)
	}
	return nil, nil
}

func (m *MockMemoryRepository) FindSimilarByVector(excludeID string, embedding []float32, limit int) ([]model.AuditMemory, error) {
	if m.FindSimilarByVectorFn != nil {
		return m.FindSimilarByVectorFn(excludeID, embedding, limit)
	}
	return nil, nil
}

func (m *MockMemoryRepository) GetMemory(id string) (*model.AuditMemory, error) {
	if m.GetMemoryFn != nil {
		return m.GetMemoryFn(id)
	}
	return nil, nil
}

func (m *MockMemoryRepository) UpdateRemediation(id string, status string, notes string) error {
	if m.UpdateRemediationFn != nil {
		return m.UpdateRemediationFn(id, status, notes)
	}
	return nil
}

func (m *MockMemoryRepository) ListMemoriesByAudit(auditID string) ([]model.AuditMemory, error) {
	if m.ListMemoriesByAuditFn != nil {
		return m.ListMemoriesByAuditFn(auditID)
	}
	return nil, nil
}

func (m *MockMemoryRepository) ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error) {
	if m.ListByCodebasePathFn != nil {
		return m.ListByCodebasePathFn(path, agentType, limit)
	}
	return nil, nil
}

func (m *MockMemoryRepository) ListRecent(limit int) ([]model.AuditMemory, error) {
	if m.ListRecentFn != nil {
		return m.ListRecentFn(limit)
	}
	return nil, nil
}

func (m *MockMemoryRepository) StoreEdge(edge *model.MemoryEdge) error {
	if m.StoreEdgeFn != nil {
		return m.StoreEdgeFn(edge)
	}
	return nil
}

func (m *MockMemoryRepository) GetEdges(memoryID string) ([]model.MemoryEdge, error) {
	if m.GetEdgesFn != nil {
		return m.GetEdgesFn(memoryID)
	}
	return nil, nil
}
