package service

import (
	"fmt"

	"github.com/vulture/backend/internal/model"
)

// AuditLineageLister is the one lineage read AuditFalsePositives needs. Both
// repository.LineageRepository and LineageService satisfy it, so the audit
// handler (which holds the repository) and the stream handler (which holds
// the service) share this read.
type AuditLineageLister interface {
	ListByAudit(auditID string) ([]model.FindingLineage, error)
}

// AuditFalsePositives reports, per finding of the audit, whether its own
// lineage row is triaged false_positive (0096 follow-up: OWASP coverage does
// not count triaged false positives). One read: ListByAudit returns the rows
// behind the audit's findings — v1 matches, and v2 matches within the audit's
// target — with merged rows excluded; model.TriagedFalsePositives resolves
// each finding to its own row, v2 first.
func AuditFalsePositives(src AuditLineageLister, auditID string, findings []model.Finding) ([]bool, error) {
	rows, err := src.ListByAudit(auditID)
	if err != nil {
		return nil, fmt.Errorf("list lineage by audit: %w", err)
	}
	return model.TriagedFalsePositives(rows, findings), nil
}
