package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// SQLiteWebhookRepo implements WebhookRepository using an existing *sql.DB.
type SQLiteWebhookRepo struct {
	db *sql.DB
}

// NewSQLiteWebhookRepo wraps an existing SQLite database for webhook delivery queries.
func NewSQLiteWebhookRepo(db *sql.DB) *SQLiteWebhookRepo {
	return &SQLiteWebhookRepo{db: db}
}

func (r *SQLiteWebhookRepo) Record(d *model.WebhookDelivery) error {
	var deliveredAt *string
	if d.DeliveredAt != nil {
		s := d.DeliveredAt.Format(time.RFC3339)
		deliveredAt = &s
	}
	_, err := r.db.Exec(
		`INSERT INTO audit_webhook_deliveries (id, audit_id, url, status, attempts, last_error, created_at, delivered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET status=?, attempts=?, last_error=?, delivered_at=?`,
		d.ID, d.AuditID, d.URL, d.Status, d.Attempts, d.LastError, d.CreatedAt.Format(time.RFC3339), deliveredAt,
		d.Status, d.Attempts, d.LastError, deliveredAt,
	)
	if err != nil {
		return fmt.Errorf("record webhook delivery: %w", err)
	}
	return nil
}

func (r *SQLiteWebhookRepo) ListByAudit(auditID string) ([]model.WebhookDelivery, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, url, status, attempts, last_error, created_at, delivered_at
		 FROM audit_webhook_deliveries WHERE audit_id = ? ORDER BY created_at`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()

	var deliveries []model.WebhookDelivery
	for rows.Next() {
		var d model.WebhookDelivery
		var createdStr string
		var deliveredStr sql.NullString
		err := rows.Scan(&d.ID, &d.AuditID, &d.URL, &d.Status,
			&d.Attempts, &d.LastError, &createdStr, &deliveredStr)
		if err != nil {
			return nil, fmt.Errorf("scan webhook delivery: %w", err)
		}
		d.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		if deliveredStr.Valid {
			t, _ := time.Parse(time.RFC3339, deliveredStr.String)
			d.DeliveredAt = &t
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}
