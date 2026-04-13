package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/vulture/backend/internal/model"
)

// PostgresDiscoverRepo implements DiscoverRepository using PostgreSQL.
type PostgresDiscoverRepo struct {
	db *sql.DB
}

// NewPostgresDiscoverRepo wraps a PostgreSQL database for discover result queries.
func NewPostgresDiscoverRepo(db *sql.DB) *PostgresDiscoverRepo {
	return &PostgresDiscoverRepo{db: db}
}

func (r *PostgresDiscoverRepo) SaveDiscoverResult(dr *model.DiscoverResult) error {
	techJSON, err := json.Marshal(dr.Technologies)
	if err != nil {
		return fmt.Errorf("marshal technologies: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO discover_results (id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (audit_id) DO UPDATE SET
			site_map_json=EXCLUDED.site_map_json, url_count=EXCLUDED.url_count,
			api_count=EXCLUDED.api_count, form_count=EXCLUDED.form_count,
			technologies=EXCLUDED.technologies`,
		dr.ID, dr.AuditID, dr.TargetURL, dr.SiteMapJSON,
		dr.URLCount, dr.APICount, dr.FormCount,
		string(techJSON), dr.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("save discover result: %w", err)
	}
	return nil
}

func (r *PostgresDiscoverRepo) GetDiscoverResult(id string) (*model.DiscoverResult, error) {
	row := r.db.QueryRow(
		`SELECT id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at
		 FROM discover_results WHERE id = $1`, id,
	)
	return scanPgDiscoverResult(row)
}

func (r *PostgresDiscoverRepo) GetDiscoverResultByAuditID(auditID string) (*model.DiscoverResult, error) {
	row := r.db.QueryRow(
		`SELECT id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at
		 FROM discover_results WHERE audit_id = $1`, auditID,
	)
	return scanPgDiscoverResult(row)
}

func (r *PostgresDiscoverRepo) GetDiscoverResultByTarget(targetURL string) (*model.DiscoverResult, error) {
	row := r.db.QueryRow(
		`SELECT id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at
		 FROM discover_results WHERE target_url = $1 ORDER BY created_at DESC LIMIT 1`, targetURL,
	)
	return scanPgDiscoverResult(row)
}

func scanPgDiscoverResult(row *sql.Row) (*model.DiscoverResult, error) {
	var dr model.DiscoverResult
	var techStr string
	err := row.Scan(
		&dr.ID, &dr.AuditID, &dr.TargetURL, &dr.SiteMapJSON,
		&dr.URLCount, &dr.APICount, &dr.FormCount,
		&techStr, &dr.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan discover result: %w", err)
	}
	_ = json.Unmarshal([]byte(techStr), &dr.Technologies)
	return &dr, nil
}
