package repository

import "github.com/vulture/backend/internal/model"

// WebhookRepository persists webhook delivery attempts for audit trail.
type WebhookRepository interface {
	Record(d *model.WebhookDelivery) error          // insert OR update by id
	ListByAudit(auditID string) ([]model.WebhookDelivery, error)
}
