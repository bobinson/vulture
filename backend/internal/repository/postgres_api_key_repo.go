package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// PostgresAPIKeyRepo implements APIKeyRepository using PostgreSQL.
type PostgresAPIKeyRepo struct {
	db *sql.DB
}

// NewPostgresAPIKeyRepo returns a new Postgres-backed API key repository.
func NewPostgresAPIKeyRepo(db *sql.DB) *PostgresAPIKeyRepo {
	return &PostgresAPIKeyRepo{db: db}
}

func (r *PostgresAPIKeyRepo) Create(k *model.APIKey) error {
	scopesJSON, err := json.Marshal(k.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO api_keys (id, prefix, hash, name, scopes, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		k.ID, k.Prefix, k.Hash, k.Name,
		string(scopesJSON), k.CreatedBy,
		k.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert api key: %w", err)
	}
	return nil
}

func (r *PostgresAPIKeyRepo) FindByPrefix(prefix string) (*model.APIKey, error) {
	row := r.db.QueryRow(
		`SELECT id, prefix, hash, name, scopes, created_by, created_at, last_used_at
		 FROM api_keys WHERE prefix = $1 AND revoked_at IS NULL`, prefix,
	)
	return scanPostgresAPIKey(row)
}

func (r *PostgresAPIKeyRepo) List(createdBy string) ([]model.APIKey, error) {
	rows, err := r.db.Query(
		`SELECT id, prefix, hash, name, scopes, created_by, created_at, last_used_at
		 FROM api_keys WHERE created_by = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC`, createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()
	return scanPostgresAPIKeys(rows)
}

func (r *PostgresAPIKeyRepo) Revoke(id string) error {
	_, err := r.db.Exec(
		`UPDATE api_keys SET revoked_at = $1 WHERE id = $2`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

func (r *PostgresAPIKeyRepo) TouchLastUsed(id string) error {
	_, _ = r.db.Exec(
		`UPDATE api_keys SET last_used_at = $1 WHERE id = $2`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	return nil
}

func scanPostgresAPIKey(row *sql.Row) (*model.APIKey, error) {
	var k model.APIKey
	var scopesJSON, createdAt string
	var lastUsedAt sql.NullString
	err := row.Scan(&k.ID, &k.Prefix, &k.Hash, &k.Name, &scopesJSON,
		&k.CreatedBy, &createdAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan api key: %w", err)
	}
	_ = json.Unmarshal([]byte(scopesJSON), &k.Scopes)
	k.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if lastUsedAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		k.LastUsedAt = &t
	}
	return &k, nil
}

func scanPostgresAPIKeys(rows *sql.Rows) ([]model.APIKey, error) {
	var keys []model.APIKey
	for rows.Next() {
		var k model.APIKey
		var scopesJSON, createdAt string
		var lastUsedAt sql.NullString
		err := rows.Scan(&k.ID, &k.Prefix, &k.Hash, &k.Name, &scopesJSON,
			&k.CreatedBy, &createdAt, &lastUsedAt)
		if err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		_ = json.Unmarshal([]byte(scopesJSON), &k.Scopes)
		k.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if lastUsedAt.Valid {
			t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
			k.LastUsedAt = &t
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
