package model

import (
	"encoding/json"
	"time"
)

type AuditStatus string

const (
	AuditStatusPending   AuditStatus = "pending"
	AuditStatusRunning   AuditStatus = "running"
	AuditStatusCompleted AuditStatus = "completed"
	AuditStatusFailed    AuditStatus = "failed"
)

type Audit struct {
	ID            string            `json:"id"`
	SourceID      string            `json:"source_id"`
	SourcePath    string            `json:"source_path,omitempty"`
	Types         []string          `json:"types"`
	Config        json.RawMessage   `json:"config"`
	Status        AuditStatus       `json:"status"`
	Findings      []Finding         `json:"findings,omitempty"`
	FindingsCount int               `json:"findings_count"`
	Scores        map[string]int    `json:"scores,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	CompletedAt   *time.Time        `json:"completed_at,omitempty"`
}

type AuditRequest struct {
	SourceID string          `json:"source_id"`
	Types    []string        `json:"types"`
	Config   json.RawMessage `json:"config"`
}
