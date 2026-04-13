package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// SQLiteDiscoverRepo implements DiscoverRepository using SQLite.
type SQLiteDiscoverRepo struct {
	db *sql.DB
}

// NewSQLiteDiscoverRepo wraps an existing SQLite database for discover result queries.
func NewSQLiteDiscoverRepo(db *sql.DB) *SQLiteDiscoverRepo {
	return &SQLiteDiscoverRepo{db: db}
}

func (r *SQLiteDiscoverRepo) SaveDiscoverResult(dr *model.DiscoverResult) error {
	techJSON, err := json.Marshal(dr.Technologies)
	if err != nil {
		return fmt.Errorf("marshal technologies: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT OR REPLACE INTO discover_results (id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dr.ID, dr.AuditID, dr.TargetURL, dr.SiteMapJSON,
		dr.URLCount, dr.APICount, dr.FormCount,
		string(techJSON), dr.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("save discover result: %w", err)
	}
	return nil
}

func (r *SQLiteDiscoverRepo) GetDiscoverResult(id string) (*model.DiscoverResult, error) {
	row := r.db.QueryRow(
		`SELECT id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at
		 FROM discover_results WHERE id = ?`, id,
	)
	return scanDiscoverResult(row)
}

func (r *SQLiteDiscoverRepo) GetDiscoverResultByAuditID(auditID string) (*model.DiscoverResult, error) {
	row := r.db.QueryRow(
		`SELECT id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at
		 FROM discover_results WHERE audit_id = ?`, auditID,
	)
	return scanDiscoverResult(row)
}

func (r *SQLiteDiscoverRepo) GetDiscoverResultByTarget(targetURL string) (*model.DiscoverResult, error) {
	row := r.db.QueryRow(
		`SELECT id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at
		 FROM discover_results WHERE target_url = ? ORDER BY created_at DESC LIMIT 1`, targetURL,
	)
	return scanDiscoverResult(row)
}

func scanDiscoverResult(row *sql.Row) (*model.DiscoverResult, error) {
	var dr model.DiscoverResult
	var techStr, createdStr string
	err := row.Scan(
		&dr.ID, &dr.AuditID, &dr.TargetURL, &dr.SiteMapJSON,
		&dr.URLCount, &dr.APICount, &dr.FormCount,
		&techStr, &createdStr,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan discover result: %w", err)
	}
	_ = json.Unmarshal([]byte(techStr), &dr.Technologies)
	dr.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	return &dr, nil
}
