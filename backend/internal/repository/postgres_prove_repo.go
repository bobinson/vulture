package repository

import (
	"database/sql"
	"fmt"

	"github.com/vulture/backend/internal/model"
)

// PostgresProveRepo implements ProveRepository using PostgreSQL.
type PostgresProveRepo struct {
	db *sql.DB
}

// NewPostgresProveRepo wraps an existing Postgres database for prove result queries.
func NewPostgresProveRepo(db *sql.DB) *PostgresProveRepo {
	return &PostgresProveRepo{db: db}
}

func (r *PostgresProveRepo) SaveProveResults(results []model.ProveResult) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO prove_results (id, audit_id, finding_id, status, evidence, iterations_used, staging_url, fingerprint, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, evidence = EXCLUDED.evidence,
		 iterations_used = EXCLUDED.iterations_used, staging_url = EXCLUDED.staging_url, fingerprint = EXCLUDED.fingerprint`,
	)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, pr := range results {
		_, err := stmt.Exec(
			pr.ID, pr.AuditID, pr.FindingID, string(pr.Status),
			pr.Evidence, pr.IterationsUsed, pr.StagingURL,
			pr.Fingerprint, pr.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert prove result: %w", err)
		}
	}
	return tx.Commit()
}

func (r *PostgresProveRepo) GetProveResults(auditID string) ([]model.ProveResult, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, finding_id, status, evidence, iterations_used, staging_url, fingerprint, created_at
		 FROM prove_results WHERE audit_id = $1 ORDER BY created_at`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("query prove results: %w", err)
	}
	defer rows.Close()

	var results []model.ProveResult
	for rows.Next() {
		var pr model.ProveResult
		err := rows.Scan(&pr.ID, &pr.AuditID, &pr.FindingID, &pr.Status,
			&pr.Evidence, &pr.IterationsUsed, &pr.StagingURL, &pr.Fingerprint, &pr.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan prove result: %w", err)
		}
		results = append(results, pr)
	}
	return results, rows.Err()
}

func (r *PostgresProveRepo) GetProveResultsByFingerprint(fingerprint string) ([]model.ProveResult, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, finding_id, status, evidence, iterations_used, staging_url, fingerprint, created_at
		 FROM prove_results WHERE fingerprint = $1 ORDER BY created_at DESC`,
		fingerprint,
	)
	if err != nil {
		return nil, fmt.Errorf("query prove results by fingerprint: %w", err)
	}
	defer rows.Close()

	var results []model.ProveResult
	for rows.Next() {
		var pr model.ProveResult
		err := rows.Scan(&pr.ID, &pr.AuditID, &pr.FindingID, &pr.Status,
			&pr.Evidence, &pr.IterationsUsed, &pr.StagingURL, &pr.Fingerprint, &pr.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan prove result: %w", err)
		}
		results = append(results, pr)
	}
	return results, rows.Err()
}

func (r *PostgresProveRepo) GetProveSummary(auditID string) (*model.ProveSummary, error) {
	row := r.db.QueryRow(
		`SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status='not_reproduced' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status='inconclusive' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status='skipped' THEN 1 ELSE 0 END), 0)
		 FROM prove_results WHERE audit_id = $1`,
		auditID,
	)
	s := &model.ProveSummary{AuditID: auditID}
	err := row.Scan(&s.Total, &s.Verified, &s.NotReproduced, &s.Inconclusive, &s.Skipped)
	if err != nil {
		return nil, fmt.Errorf("scan prove summary: %w", err)
	}
	return s, nil
}
