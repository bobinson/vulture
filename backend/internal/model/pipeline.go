package model

import (
	"encoding/json"
	"time"
)

// PipelineStatus represents the current state of a multi-stage pipeline.
type PipelineStatus string

const (
	PipelineStatusPending          PipelineStatus = "pending"
	PipelineStatusScanRunning      PipelineStatus = "scan_running"
	PipelineStatusDiscoverRunning  PipelineStatus = "discover_running"
	PipelineStatusProveRunning     PipelineStatus = "prove_running"
	PipelineStatusCompleted        PipelineStatus = "completed"
	PipelineStatusFailed           PipelineStatus = "failed"
)

// Pipeline represents a multi-stage audit pipeline (scan → discover → prove).
type Pipeline struct {
	ID              string          `json:"id"`
	TargetURL       string          `json:"target_url"`
	SourceID        string          `json:"source_id"`
	Stages          []string        `json:"stages"`
	Config          json.RawMessage `json:"config"`
	ScanAuditID     string          `json:"scan_audit_id,omitempty"`
	DiscoverAuditID string          `json:"discover_audit_id,omitempty"`
	ProveAuditID    string          `json:"prove_audit_id,omitempty"`
	Status          PipelineStatus  `json:"status"`
	CreatedAt       time.Time       `json:"created_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
}

// PipelineRequest is the input for creating a new pipeline.
type PipelineRequest struct {
	SourceID  string          `json:"source_id"`
	TargetURL string          `json:"target_url"`
	Stages    []string        `json:"stages"`
	Config    json.RawMessage `json:"config,omitempty"`
}
