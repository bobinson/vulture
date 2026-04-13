package repository

import "github.com/vulture/backend/internal/model"

// LineageRepository defines persistence operations for finding lineage tracking.
type LineageRepository interface {
	UpsertLineage(l *model.FindingLineage) error
	GetLineage(id string) (*model.FindingLineage, error)
	GetLineageByFingerprint(fingerprint, sourcePath, agentType string) (*model.FindingLineage, error)
	GetLineageByFingerprints(fingerprints []string, sourcePath string) (map[string]*model.FindingLineage, error)
	ListBySourcePath(sourcePath, status string, limit, offset int) ([]model.FindingLineage, error)
	ListByAudit(auditID string) ([]model.FindingLineage, error)
	UpdateStatus(id string, status string, notes string, ticketURL string) error
	MarkFixed(id, auditID, commit string) error
	MarkRegression(id, auditID, commit string) error
	GetOpenBySourcePath(sourcePath, agentType string) ([]model.FindingLineage, error)
	AddEvent(e *model.LineageEvent) error
	GetEvents(lineageID string) ([]model.LineageEvent, error)
}
