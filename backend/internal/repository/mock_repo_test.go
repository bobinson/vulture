package repository

import (
	"errors"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func TestMockAuditRepository_DefaultBehavior(t *testing.T) {
	mock := &MockAuditRepository{}

	// All defaults return nil
	if err := mock.CreateSource(&model.Source{}); err != nil {
		t.Errorf("CreateSource: %v", err)
	}
	src, err := mock.GetSource("id")
	if err != nil || src != nil {
		t.Errorf("GetSource: src=%v err=%v", src, err)
	}
	src, err = mock.FindSourceByPath("/path")
	if err != nil || src != nil {
		t.Errorf("FindSourceByPath: src=%v err=%v", src, err)
	}
	if err := mock.CreateAudit(&model.Audit{}); err != nil {
		t.Errorf("CreateAudit: %v", err)
	}
	a, err := mock.GetAudit("id")
	if err != nil || a != nil {
		t.Errorf("GetAudit: a=%v err=%v", a, err)
	}
	if err := mock.UpdateAudit(&model.Audit{}); err != nil {
		t.Errorf("UpdateAudit: %v", err)
	}
	if err := mock.SaveFindings("id", nil); err != nil {
		t.Errorf("SaveFindings: %v", err)
	}
	audits, err := mock.ListAudits(10, 0)
	if err != nil || audits != nil {
		t.Errorf("ListAudits: audits=%v err=%v", audits, err)
	}
	stats, err := mock.GetStats()
	if err != nil || stats != nil {
		t.Errorf("GetStats: stats=%v err=%v", stats, err)
	}
	ca, err := mock.GetLatestCompletedAudit("src", []string{"chaos"})
	if err != nil || ca != nil {
		t.Errorf("GetLatestCompletedAudit: ca=%v err=%v", ca, err)
	}
	pa, err := mock.GetPreviousCompletedAudit("src", []string{"chaos"}, "exclude")
	if err != nil || pa != nil {
		t.Errorf("GetPreviousCompletedAudit: pa=%v err=%v", pa, err)
	}
	spa, err := mock.ListAuditsBySourcePath("/path", 10, 0)
	if err != nil || spa != nil {
		t.Errorf("ListAuditsBySourcePath: spa=%v err=%v", spa, err)
	}
}

func TestMockAuditRepository_WithFunctions(t *testing.T) {
	repoErr := errors.New("test error")
	mock := &MockAuditRepository{
		CreateSourceFn: func(s *model.Source) error { return repoErr },
		GetSourceFn:    func(id string) (*model.Source, error) { return nil, repoErr },
		FindSourceByPathFn: func(path string) (*model.Source, error) {
			return &model.Source{ID: "s1"}, nil
		},
		CreateAuditFn:  func(a *model.Audit) error { return repoErr },
		GetAuditFn:     func(id string) (*model.Audit, error) { return nil, repoErr },
		UpdateAuditFn:  func(a *model.Audit) error { return repoErr },
		SaveFindingsFn: func(id string, f []model.Finding) error { return repoErr },
		ListAuditsFn:   func(l, o int) ([]model.Audit, error) { return nil, repoErr },
		GetStatsFn:     func() (*model.DashboardStats, error) { return nil, repoErr },
		GetLatestCompletedAuditFn: func(srcID string, types []string) (*model.Audit, error) {
			return nil, repoErr
		},
		GetPreviousCompletedAuditFn: func(srcID string, types []string, excludeID string) (*model.Audit, error) {
			return nil, repoErr
		},
		ListAuditsBySourcePathFn: func(path string, l, o int) ([]model.Audit, error) {
			return nil, repoErr
		},
	}

	if err := mock.CreateSource(&model.Source{}); !errors.Is(err, repoErr) {
		t.Errorf("CreateSource: expected repoErr, got %v", err)
	}
	if _, err := mock.GetSource("id"); !errors.Is(err, repoErr) {
		t.Errorf("GetSource: expected repoErr, got %v", err)
	}
	src, _ := mock.FindSourceByPath("/path")
	if src == nil || src.ID != "s1" {
		t.Errorf("FindSourceByPath: expected s1, got %v", src)
	}
	if err := mock.CreateAudit(&model.Audit{}); !errors.Is(err, repoErr) {
		t.Errorf("CreateAudit: expected repoErr, got %v", err)
	}
	if _, err := mock.GetAudit("id"); !errors.Is(err, repoErr) {
		t.Errorf("GetAudit: expected repoErr, got %v", err)
	}
	if err := mock.UpdateAudit(&model.Audit{}); !errors.Is(err, repoErr) {
		t.Errorf("UpdateAudit: expected repoErr, got %v", err)
	}
	if err := mock.SaveFindings("id", nil); !errors.Is(err, repoErr) {
		t.Errorf("SaveFindings: expected repoErr, got %v", err)
	}
	if _, err := mock.ListAudits(10, 0); !errors.Is(err, repoErr) {
		t.Errorf("ListAudits: expected repoErr, got %v", err)
	}
	if _, err := mock.GetStats(); !errors.Is(err, repoErr) {
		t.Errorf("GetStats: expected repoErr, got %v", err)
	}
	if _, err := mock.GetLatestCompletedAudit("src", []string{"chaos"}); !errors.Is(err, repoErr) {
		t.Errorf("GetLatestCompletedAudit: expected repoErr, got %v", err)
	}
	if _, err := mock.GetPreviousCompletedAudit("src", []string{"chaos"}, "exclude"); !errors.Is(err, repoErr) {
		t.Errorf("GetPreviousCompletedAudit: expected repoErr, got %v", err)
	}
	if _, err := mock.ListAuditsBySourcePath("/path", 10, 0); !errors.Is(err, repoErr) {
		t.Errorf("ListAuditsBySourcePath: expected repoErr, got %v", err)
	}
}

func TestMockMemoryRepository_DefaultBehavior(t *testing.T) {
	mock := &MockMemoryRepository{}

	if err := mock.StoreMemory(&model.AuditMemory{}); err != nil {
		t.Errorf("StoreMemory: %v", err)
	}
	if err := mock.StoreEmbedding("id", nil); err != nil {
		t.Errorf("StoreEmbedding: %v", err)
	}
	mems, err := mock.SearchMemories("q", nil, 10)
	if err != nil || mems != nil {
		t.Errorf("SearchMemories: mems=%v err=%v", mems, err)
	}
	mems, err = mock.HybridSearchMemories("q", nil, 10)
	if err != nil || mems != nil {
		t.Errorf("HybridSearchMemories: mems=%v err=%v", mems, err)
	}
	mems, err = mock.FindSimilarByVector("id", nil, 10)
	if err != nil || mems != nil {
		t.Errorf("FindSimilarByVector: mems=%v err=%v", mems, err)
	}
	mem, err := mock.GetMemory("id")
	if err != nil || mem != nil {
		t.Errorf("GetMemory: mem=%v err=%v", mem, err)
	}
	if err := mock.UpdateRemediation("id", "status", "notes"); err != nil {
		t.Errorf("UpdateRemediation: %v", err)
	}
	mems, err = mock.ListMemoriesByAudit("audit-id")
	if err != nil || mems != nil {
		t.Errorf("ListMemoriesByAudit: mems=%v err=%v", mems, err)
	}
	mems, err = mock.ListByCodebasePath("/path", "owasp", 10)
	if err != nil || mems != nil {
		t.Errorf("ListByCodebasePath: mems=%v err=%v", mems, err)
	}
	mems, err = mock.ListRecent(10)
	if err != nil || mems != nil {
		t.Errorf("ListRecent: mems=%v err=%v", mems, err)
	}
	if err := mock.StoreEdge(&model.MemoryEdge{}); err != nil {
		t.Errorf("StoreEdge: %v", err)
	}
	edges, err := mock.GetEdges("id")
	if err != nil || edges != nil {
		t.Errorf("GetEdges: edges=%v err=%v", edges, err)
	}
}

func TestMockMemoryRepository_WithFunctions(t *testing.T) {
	repoErr := errors.New("test error")
	mock := &MockMemoryRepository{
		StoreMemoryFn: func(m *model.AuditMemory) error { return repoErr },
		StoreEmbeddingFn: func(id string, emb []float32) error { return repoErr },
		SearchMemoriesFn: func(q string, emb []float32, l int) ([]model.AuditMemory, error) {
			return nil, repoErr
		},
		FindSimilarByVectorFn: func(id string, emb []float32, l int) ([]model.AuditMemory, error) {
			return nil, repoErr
		},
		GetMemoryFn: func(id string) (*model.AuditMemory, error) { return nil, repoErr },
		UpdateRemediationFn: func(id, status, notes string) error { return repoErr },
		ListMemoriesByAuditFn: func(id string) ([]model.AuditMemory, error) {
			return nil, repoErr
		},
		ListByCodebasePathFn: func(path, agent string, l int) ([]model.AuditMemory, error) {
			return nil, repoErr
		},
		ListRecentFn: func(l int) ([]model.AuditMemory, error) { return nil, repoErr },
		StoreEdgeFn:  func(e *model.MemoryEdge) error { return repoErr },
		GetEdgesFn:   func(id string) ([]model.MemoryEdge, error) { return nil, repoErr },
	}

	if err := mock.StoreMemory(&model.AuditMemory{}); !errors.Is(err, repoErr) {
		t.Errorf("StoreMemory: expected repoErr, got %v", err)
	}
	if err := mock.StoreEmbedding("id", nil); !errors.Is(err, repoErr) {
		t.Errorf("StoreEmbedding: expected repoErr, got %v", err)
	}
	if _, err := mock.SearchMemories("q", nil, 10); !errors.Is(err, repoErr) {
		t.Errorf("SearchMemories: expected repoErr, got %v", err)
	}
	if _, err := mock.FindSimilarByVector("id", nil, 10); !errors.Is(err, repoErr) {
		t.Errorf("FindSimilarByVector: expected repoErr, got %v", err)
	}
	if _, err := mock.GetMemory("id"); !errors.Is(err, repoErr) {
		t.Errorf("GetMemory: expected repoErr, got %v", err)
	}
	if err := mock.UpdateRemediation("id", "s", "n"); !errors.Is(err, repoErr) {
		t.Errorf("UpdateRemediation: expected repoErr, got %v", err)
	}
	if _, err := mock.ListMemoriesByAudit("id"); !errors.Is(err, repoErr) {
		t.Errorf("ListMemoriesByAudit: expected repoErr, got %v", err)
	}
	if _, err := mock.ListByCodebasePath("/p", "o", 10); !errors.Is(err, repoErr) {
		t.Errorf("ListByCodebasePath: expected repoErr, got %v", err)
	}
	if _, err := mock.ListRecent(10); !errors.Is(err, repoErr) {
		t.Errorf("ListRecent: expected repoErr, got %v", err)
	}
	if err := mock.StoreEdge(&model.MemoryEdge{}); !errors.Is(err, repoErr) {
		t.Errorf("StoreEdge: expected repoErr, got %v", err)
	}
	if _, err := mock.GetEdges("id"); !errors.Is(err, repoErr) {
		t.Errorf("GetEdges: expected repoErr, got %v", err)
	}
}
