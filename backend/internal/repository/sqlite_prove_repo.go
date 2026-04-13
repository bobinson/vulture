package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// SQLiteProveRepo implements ProveRepository using an existing *sql.DB.
type SQLiteProveRepo struct {
	db *sql.DB
}

// NewSQLiteProveRepo wraps an existing SQLite database for prove result queries.
func NewSQLiteProveRepo(db *sql.DB) *SQLiteProveRepo {
	return &SQLiteProveRepo{db: db}
}

func (r *SQLiteProveRepo) SaveProveResults(results []model.ProveResult) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR REPLACE INTO prove_results (id, audit_id, finding_id, status, evidence, iterations_used, staging_url, fingerprint, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, pr := range results {
		_, err := stmt.Exec(
			pr.ID, pr.AuditID, pr.FindingID, string(pr.Status),
			pr.Evidence, pr.IterationsUsed, pr.StagingURL,
			pr.Fingerprint, pr.CreatedAt.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("insert prove result: %w", err)
		}
	}
	return tx.Commit()
}

func (r *SQLiteProveRepo) GetProveResults(auditID string) ([]model.ProveResult, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, finding_id, status, evidence, iterations_used, staging_url, fingerprint, created_at
		 FROM prove_results WHERE audit_id = ? ORDER BY created_at`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("query prove results: %w", err)
	}
	defer rows.Close()

	var results []model.ProveResult
	for rows.Next() {
		var pr model.ProveResult
		var createdStr string
		err := rows.Scan(&pr.ID, &pr.AuditID, &pr.FindingID, &pr.Status,
			&pr.Evidence, &pr.IterationsUsed, &pr.StagingURL, &pr.Fingerprint, &createdStr)
		if err != nil {
			return nil, fmt.Errorf("scan prove result: %w", err)
		}
		pr.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		results = append(results, pr)
	}
	return results, rows.Err()
}

func (r *SQLiteProveRepo) GetProveResultsByFingerprint(fingerprint string) ([]model.ProveResult, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, finding_id, status, evidence, iterations_used, staging_url, fingerprint, created_at
		 FROM prove_results WHERE fingerprint = ? ORDER BY created_at DESC`,
		fingerprint,
	)
	if err != nil {
		return nil, fmt.Errorf("query prove results by fingerprint: %w", err)
	}
	defer rows.Close()

	var results []model.ProveResult
	for rows.Next() {
		var pr model.ProveResult
		var createdStr string
		err := rows.Scan(&pr.ID, &pr.AuditID, &pr.FindingID, &pr.Status,
			&pr.Evidence, &pr.IterationsUsed, &pr.StagingURL, &pr.Fingerprint, &createdStr)
		if err != nil {
			return nil, fmt.Errorf("scan prove result: %w", err)
		}
		pr.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		results = append(results, pr)
	}
	return results, rows.Err()
}

func (r *SQLiteProveRepo) GetProveSummary(auditID string) (*model.ProveSummary, error) {
	row := r.db.QueryRow(
		`SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status='not_reproduced' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status='inconclusive' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status='skipped' THEN 1 ELSE 0 END), 0)
		 FROM prove_results WHERE audit_id = ?`,
		auditID,
	)
	s := &model.ProveSummary{AuditID: auditID}
	err := row.Scan(&s.Total, &s.Verified, &s.NotReproduced, &s.Inconclusive, &s.Skipped)
	if err != nil {
		return nil, fmt.Errorf("scan prove summary: %w", err)
	}
	return s, nil
}
