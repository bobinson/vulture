package repository

import "github.com/vulture/backend/internal/model"

type AuditRepository interface {
	CreateSource(source *model.Source) error
	GetSource(id string) (*model.Source, error)
	FindSourceByPath(path string) (*model.Source, error)
	UpdateSourceGitInfo(id string, branch, commitHash, commitShort, remoteURL string) error
	CreateAudit(audit *model.Audit) error
	GetAudit(id string) (*model.Audit, error)
	UpdateAudit(audit *model.Audit) error
	SaveFindings(auditID string, findings []model.Finding) error
	ListAudits(limit, offset int) ([]model.Audit, error)
	GetStats() (*model.DashboardStats, error)
	GetLatestCompletedAudit(sourceID string, types []string) (*model.Audit, error)
}

type MemoryRepository interface {
	StoreMemory(mem *model.AuditMemory) error
	StoreEmbedding(id string, embedding []float32) error
	SearchMemories(query string, embedding []float32, limit int) ([]model.AuditMemory, error)
	FindSimilarByVector(excludeID string, embedding []float32, limit int) ([]model.AuditMemory, error)
	GetMemory(id string) (*model.AuditMemory, error)
	UpdateRemediation(id string, status string, notes string) error
	ListMemoriesByAudit(auditID string) ([]model.AuditMemory, error)
	ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error)
	ListRecent(limit int) ([]model.AuditMemory, error)
	StoreEdge(edge *model.MemoryEdge) error
	GetEdges(memoryID string) ([]model.MemoryEdge, error)
}
