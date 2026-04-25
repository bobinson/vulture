package repository

import "github.com/vulture/backend/internal/model"

// MockWebhookRepository implements WebhookRepository for testing.
type MockWebhookRepository struct {
	RecordFn      func(*model.WebhookDelivery) error
	ListByAuditFn func(string) ([]model.WebhookDelivery, error)

	// Recorded stores all deliveries passed to Record for test assertions.
	Recorded []*model.WebhookDelivery
}

func (m *MockWebhookRepository) Record(d *model.WebhookDelivery) error {
	m.Recorded = append(m.Recorded, d)
	if m.RecordFn != nil {
		return m.RecordFn(d)
	}
	return nil
}

func (m *MockWebhookRepository) ListByAudit(auditID string) ([]model.WebhookDelivery, error) {
	if m.ListByAuditFn != nil {
		return m.ListByAuditFn(auditID)
	}
	return nil, nil
}
