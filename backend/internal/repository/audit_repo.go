package repository

import "github.com/vulture/backend/internal/model"

type AuditRepository interface {
	CreateSource(source *model.Source) error
	GetSource(id string) (*model.Source, error)
	FindSourceByPath(path string) (*model.Source, error)
	UpdateSourceGitInfo(id string, branch, commitHash, commitShort, remoteURL string) error
	// UpdateSourceTargetKey records the canonical target identity on a source
	// row (feature 0091 §7.1). Separate from UpdateSourceGitInfo because a
	// source acquires a target key on RE-ingest too: every row written before
	// 0091 has none, and the key is what lineage groups by.
	UpdateSourceTargetKey(id, targetKey string) error
	CreateAudit(audit *model.Audit) error
	GetAudit(id string) (*model.Audit, error)
	UpdateAudit(audit *model.Audit) error
	SaveFindings(auditID string, findings []model.Finding) error
	ListAudits(limit, offset int) ([]model.Audit, error)
	GetStats() (*model.DashboardStats, error)
	GetLatestCompletedAudit(sourceID string, types []string) (*model.Audit, error)
	GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error)
	ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error)
}

type ProveRepository interface {
	SaveProveResults(results []model.ProveResult) error
	GetProveResults(auditID string) ([]model.ProveResult, error)
	GetProveResultsByFingerprint(fingerprint string) ([]model.ProveResult, error)
	GetProveSummary(auditID string) (*model.ProveSummary, error)
}

type MemoryRepository interface {
	StoreMemory(mem *model.AuditMemory) error
	StoreEmbedding(id string, embedding []float32) error
	SearchMemories(query string, embedding []float32, limit int) ([]model.AuditMemory, error)
	HybridSearchMemories(query string, embedding []float32, limit int) ([]model.AuditMemory, error)
	FindSimilarByVector(excludeID string, embedding []float32, limit int) ([]model.AuditMemory, error)
	GetMemory(id string) (*model.AuditMemory, error)
	UpdateRemediation(id string, status string, notes string) error
	// SetRemediationStatus propagates a lineage transition onto every memory
	// row sharing the finding's fingerprint (feature 0091 §8). Keyed by
	// fingerprint, not id, because lineage and memory are two records of the
	// same finding and only the fingerprint joins them.
	//
	// Separate from UpdateRemediation, which is the USER path: that one takes
	// a memory id, writes remediation_notes, and nudges confidence_score.
	// A scanner-driven status change must do none of those things.
	SetRemediationStatus(fingerprint string, status string) error
	ListMemoriesByAudit(auditID string) ([]model.AuditMemory, error)
	ListByCodebasePath(path string, agentType string, limit int) ([]model.AuditMemory, error)
	ListByCodebasePathMulti(path string, agentTypes []string, limit int) (map[string][]model.AuditMemory, error)
	StoreBatch(memories []*model.AuditMemory) error
	ListRecent(limit int) ([]model.AuditMemory, error)
	StoreEdge(edge *model.MemoryEdge) error
	GetEdges(memoryID string) ([]model.MemoryEdge, error)
}
