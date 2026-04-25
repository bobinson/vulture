package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

// SQLiteAPIKeyRepo implements APIKeyRepository using SQLite.
type SQLiteAPIKeyRepo struct {
	db *sql.DB
}

// NewSQLiteAPIKeyRepo returns a new SQLite-backed API key repository.
// Migration is handled by migrateAddColumns in sqlite_repo.go.
func NewSQLiteAPIKeyRepo(db *sql.DB) *SQLiteAPIKeyRepo {
	return &SQLiteAPIKeyRepo{db: db}
}

func (r *SQLiteAPIKeyRepo) Create(k *model.APIKey) error {
	scopesJSON, err := json.Marshal(k.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO api_keys (id, prefix, hash, name, scopes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Prefix, k.Hash, k.Name,
		string(scopesJSON), k.CreatedBy,
		k.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert api key: %w", err)
	}
	return nil
}

func (r *SQLiteAPIKeyRepo) FindByPrefix(prefix string) (*model.APIKey, error) {
	row := r.db.QueryRow(
		`SELECT id, prefix, hash, name, scopes, created_by, created_at, last_used_at
		 FROM api_keys WHERE prefix = ? AND revoked_at IS NULL`, prefix,
	)
	return scanSQLiteAPIKey(row)
}

func (r *SQLiteAPIKeyRepo) List(createdBy string) ([]model.APIKey, error) {
	rows, err := r.db.Query(
		`SELECT id, prefix, hash, name, scopes, created_by, created_at, last_used_at
		 FROM api_keys WHERE created_by = ? AND revoked_at IS NULL
		 ORDER BY created_at DESC`, createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()
	return scanSQLiteAPIKeys(rows)
}

func (r *SQLiteAPIKeyRepo) Revoke(id string) error {
	_, err := r.db.Exec(
		`UPDATE api_keys SET revoked_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

func (r *SQLiteAPIKeyRepo) TouchLastUsed(id string) error {
	_, _ = r.db.Exec(
		`UPDATE api_keys SET last_used_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	return nil
}

func scanSQLiteAPIKey(row *sql.Row) (*model.APIKey, error) {
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

func scanSQLiteAPIKeys(rows *sql.Rows) ([]model.APIKey, error) {
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
