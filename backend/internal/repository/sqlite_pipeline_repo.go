package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// SQLitePipelineRepo implements PipelineRepository using SQLite.
type SQLitePipelineRepo struct {
	db *sql.DB
}

// NewSQLitePipelineRepo wraps an existing SQLite database for pipeline queries.
func NewSQLitePipelineRepo(db *sql.DB) *SQLitePipelineRepo {
	return &SQLitePipelineRepo{db: db}
}

func (r *SQLitePipelineRepo) CreatePipeline(p *model.Pipeline) error {
	stagesJSON, err := json.Marshal(p.Stages)
	if err != nil {
		return fmt.Errorf("marshal stages: %w", err)
	}
	configStr := "{}"
	if p.Config != nil {
		configStr = string(p.Config)
	}
	_, err = r.db.Exec(
		`INSERT INTO pipelines (id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.TargetURL, p.SourceID, string(stagesJSON), configStr,
		p.ScanAuditID, p.DiscoverAuditID, p.ProveAuditID,
		string(p.Status), p.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert pipeline: %w", err)
	}
	return nil
}

func (r *SQLitePipelineRepo) GetPipeline(id string) (*model.Pipeline, error) {
	row := r.db.QueryRow(
		`SELECT id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at, completed_at
		 FROM pipelines WHERE id = ?`, id,
	)
	return scanPipeline(row)
}

func (r *SQLitePipelineRepo) UpdatePipeline(p *model.Pipeline) error {
	stagesJSON, err := json.Marshal(p.Stages)
	if err != nil {
		return fmt.Errorf("marshal stages: %w", err)
	}
	configStr := "{}"
	if p.Config != nil {
		configStr = string(p.Config)
	}
	var completedStr *string
	if p.CompletedAt != nil {
		s := p.CompletedAt.Format(time.RFC3339)
		completedStr = &s
	}
	_, err = r.db.Exec(
		`UPDATE pipelines SET target_url=?, source_id=?, stages=?, config=?,
			scan_audit_id=?, discover_audit_id=?, prove_audit_id=?,
			status=?, completed_at=?
		 WHERE id=?`,
		p.TargetURL, p.SourceID, string(stagesJSON), configStr,
		p.ScanAuditID, p.DiscoverAuditID, p.ProveAuditID,
		string(p.Status), completedStr, p.ID,
	)
	if err != nil {
		return fmt.Errorf("update pipeline: %w", err)
	}
	return nil
}

func (r *SQLitePipelineRepo) ListPipelines(limit, offset int) ([]model.Pipeline, error) {
	rows, err := r.db.Query(
		`SELECT id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at, completed_at
		 FROM pipelines ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list pipelines: %w", err)
	}
	defer rows.Close()
	return scanPipelines(rows)
}

func (r *SQLitePipelineRepo) GetPipelineByAuditID(auditID string) (*model.Pipeline, error) {
	row := r.db.QueryRow(
		`SELECT id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at, completed_at
		 FROM pipelines WHERE scan_audit_id=? OR discover_audit_id=? OR prove_audit_id=?`,
		auditID, auditID, auditID,
	)
	return scanPipeline(row)
}

// scanPipeline reads a single pipeline row.
func scanPipeline(row *sql.Row) (*model.Pipeline, error) {
	var p model.Pipeline
	var stagesStr, configStr, createdStr string
	var completedStr sql.NullString
	err := row.Scan(
		&p.ID, &p.TargetURL, &p.SourceID, &stagesStr, &configStr,
		&p.ScanAuditID, &p.DiscoverAuditID, &p.ProveAuditID,
		&p.Status, &createdStr, &completedStr,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan pipeline: %w", err)
	}
	_ = json.Unmarshal([]byte(stagesStr), &p.Stages)
	p.Config = json.RawMessage(configStr)
	p.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	if completedStr.Valid {
		t, _ := time.Parse(time.RFC3339, completedStr.String)
		p.CompletedAt = &t
	}
	return &p, nil
}

// scanPipelines reads multiple pipeline rows.
func scanPipelines(rows *sql.Rows) ([]model.Pipeline, error) {
	var pipelines []model.Pipeline
	for rows.Next() {
		var p model.Pipeline
		var stagesStr, configStr, createdStr string
		var completedStr sql.NullString
		err := rows.Scan(
			&p.ID, &p.TargetURL, &p.SourceID, &stagesStr, &configStr,
			&p.ScanAuditID, &p.DiscoverAuditID, &p.ProveAuditID,
			&p.Status, &createdStr, &completedStr,
		)
		if err != nil {
			return nil, fmt.Errorf("scan pipeline row: %w", err)
		}
		_ = json.Unmarshal([]byte(stagesStr), &p.Stages)
		p.Config = json.RawMessage(configStr)
		p.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		if completedStr.Valid {
			t, _ := time.Parse(time.RFC3339, completedStr.String)
			p.CompletedAt = &t
		}
		pipelines = append(pipelines, p)
	}
	return pipelines, rows.Err()
}
