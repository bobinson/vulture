package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// PostgresPipelineRepo implements PipelineRepository using PostgreSQL.
type PostgresPipelineRepo struct {
	db *sql.DB
}

// NewPostgresPipelineRepo wraps a PostgreSQL database for pipeline queries.
func NewPostgresPipelineRepo(db *sql.DB) *PostgresPipelineRepo {
	return &PostgresPipelineRepo{db: db}
}

func (r *PostgresPipelineRepo) CreatePipeline(p *model.Pipeline) error {
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
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		p.ID, p.TargetURL, p.SourceID, string(stagesJSON), configStr,
		p.ScanAuditID, p.DiscoverAuditID, p.ProveAuditID,
		string(p.Status), p.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert pipeline: %w", err)
	}
	return nil
}

func (r *PostgresPipelineRepo) GetPipeline(id string) (*model.Pipeline, error) {
	row := r.db.QueryRow(
		`SELECT id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at, completed_at
		 FROM pipelines WHERE id = $1`, id,
	)
	return scanPostgresPipeline(row)
}

func (r *PostgresPipelineRepo) UpdatePipeline(p *model.Pipeline) error {
	stagesJSON, err := json.Marshal(p.Stages)
	if err != nil {
		return fmt.Errorf("marshal stages: %w", err)
	}
	configStr := "{}"
	if p.Config != nil {
		configStr = string(p.Config)
	}
	_, err = r.db.Exec(
		`UPDATE pipelines SET target_url=$1, source_id=$2, stages=$3, config=$4,
			scan_audit_id=$5, discover_audit_id=$6, prove_audit_id=$7,
			status=$8, completed_at=$9
		 WHERE id=$10`,
		p.TargetURL, p.SourceID, string(stagesJSON), configStr,
		p.ScanAuditID, p.DiscoverAuditID, p.ProveAuditID,
		string(p.Status), p.CompletedAt, p.ID,
	)
	if err != nil {
		return fmt.Errorf("update pipeline: %w", err)
	}
	return nil
}

func (r *PostgresPipelineRepo) ListPipelines(limit, offset int) ([]model.Pipeline, error) {
	rows, err := r.db.Query(
		`SELECT id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at, completed_at
		 FROM pipelines ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list pipelines: %w", err)
	}
	defer rows.Close()
	return scanPostgresPipelines(rows)
}

func (r *PostgresPipelineRepo) GetPipelineByAuditID(auditID string) (*model.Pipeline, error) {
	row := r.db.QueryRow(
		`SELECT id, target_url, source_id, stages, config, scan_audit_id, discover_audit_id, prove_audit_id, status, created_at, completed_at
		 FROM pipelines WHERE scan_audit_id=$1 OR discover_audit_id=$1 OR prove_audit_id=$1`,
		auditID,
	)
	return scanPostgresPipeline(row)
}

func scanPostgresPipeline(row *sql.Row) (*model.Pipeline, error) {
	var p model.Pipeline
	var stagesStr, configStr string
	var completedAt *time.Time
	err := row.Scan(
		&p.ID, &p.TargetURL, &p.SourceID, &stagesStr, &configStr,
		&p.ScanAuditID, &p.DiscoverAuditID, &p.ProveAuditID,
		&p.Status, &p.CreatedAt, &completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan pipeline: %w", err)
	}
	_ = json.Unmarshal([]byte(stagesStr), &p.Stages)
	p.Config = json.RawMessage(configStr)
	p.CompletedAt = completedAt
	return &p, nil
}

func scanPostgresPipelines(rows *sql.Rows) ([]model.Pipeline, error) {
	var pipelines []model.Pipeline
	for rows.Next() {
		var p model.Pipeline
		var stagesStr, configStr string
		var completedAt *time.Time
		err := rows.Scan(
			&p.ID, &p.TargetURL, &p.SourceID, &stagesStr, &configStr,
			&p.ScanAuditID, &p.DiscoverAuditID, &p.ProveAuditID,
			&p.Status, &p.CreatedAt, &completedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan pipeline row: %w", err)
		}
		_ = json.Unmarshal([]byte(stagesStr), &p.Stages)
		p.Config = json.RawMessage(configStr)
		p.CompletedAt = completedAt
		pipelines = append(pipelines, p)
	}
	return pipelines, rows.Err()
}
