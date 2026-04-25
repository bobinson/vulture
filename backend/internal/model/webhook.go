package model

import "time"

// WebhookDelivery tracks a single delivery attempt of an audit-completion webhook.
type WebhookDelivery struct {
	ID          string
	AuditID     string
	URL         string
	Status      string // "pending" | "delivered" | "failed"
	Attempts    int
	LastError   string
	CreatedAt   time.Time
	DeliveredAt *time.Time
}

// WebhookPayload is the JSON body POSTed to the subscriber.
type WebhookPayload struct {
	AuditID       string         `json:"audit_id"`
	Status        string         `json:"status"` // "completed" | "failed"
	FindingsCount int            `json:"findings_count"`
	Scores        map[string]int `json:"scores"`
	CompletedAt   time.Time      `json:"completed_at"`
}
