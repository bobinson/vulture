package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository/migrations"

	"github.com/lib/pq"
)

type PostgresRepo struct {
	db *sql.DB
}

// NewPostgresRepo opens a connection to Postgres and applies pending
// schema migrations before returning. Use this for read/write backend
// instances (modes A and B). For read-only viewer instances (mode C),
// use NewPostgresRepoReadOnly to skip the migration step (the writer
// instance owns the schema; viewer DB users typically lack DDL perms).
func NewPostgresRepo(dsn string) (*PostgresRepo, error) {
	return newPostgresRepo(dsn, true)
}

// NewPostgresRepoReadOnly opens a Postgres connection without applying
// migrations. Used by the read-only viewer (feature 0030 / mode C),
// which connects to a DB already migrated by the writer instance.
func NewPostgresRepoReadOnly(dsn string) (*PostgresRepo, error) {
	return newPostgresRepo(dsn, false)
}

func newPostgresRepo(dsn string, applyMigrations bool) (*PostgresRepo, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(10 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if applyMigrations {
		// Apply pending schema migrations before any application code runs.
		// Concurrent backend starts serialize via a Postgres advisory lock;
		// a failed migration aborts startup with a descriptive error.
		if err := migrations.Apply(context.Background(), db, migrations.Postgres); err != nil {
			db.Close()
			return nil, fmt.Errorf("apply migrations: %w", err)
		}
	}
	return &PostgresRepo{db: db}, nil
}

func (r *PostgresRepo) Close() error {
	return r.db.Close()
}

// DB returns the underlying *sql.DB for reuse by other repositories.
func (r *PostgresRepo) DB() *sql.DB {
	return r.db
}

func (r *PostgresRepo) CreateSource(src *model.Source) error {
	_, err := r.db.Exec(
		`INSERT INTO sources (id, type, url, path, file_count, git_branch, git_commit_hash, git_commit_short, git_remote_url, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		src.ID, string(src.Type), src.URL, src.Path, src.FileCount,
		src.GitBranch, src.GitCommitHash, src.GitCommitShort, src.GitRemoteURL,
		src.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert source: %w", err)
	}
	return nil
}

func (r *PostgresRepo) UpdateSourceGitInfo(id string, branch, commitHash, commitShort, remoteURL string) error {
	_, err := r.db.Exec(
		`UPDATE sources SET git_branch = $1, git_commit_hash = $2, git_commit_short = $3, git_remote_url = $4 WHERE id = $5`,
		branch, commitHash, commitShort, remoteURL, id,
	)
	if err != nil {
		return fmt.Errorf("update source git info: %w", err)
	}
	return nil
}

func (r *PostgresRepo) GetSource(id string) (*model.Source, error) {
	row := r.db.QueryRow(
		`SELECT id, type, COALESCE(url, ''), path, file_count,
		        COALESCE(git_branch, ''), COALESCE(git_commit_hash, ''), COALESCE(git_commit_short, ''), COALESCE(git_remote_url, ''),
		        created_at
		 FROM sources WHERE id = $1`, id)
	var src model.Source
	err := row.Scan(&src.ID, &src.Type, &src.URL, &src.Path, &src.FileCount,
		&src.GitBranch, &src.GitCommitHash, &src.GitCommitShort, &src.GitRemoteURL,
		&src.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan source: %w", err)
	}
	return &src, nil
}

func (r *PostgresRepo) FindSourceByPath(path string) (*model.Source, error) {
	row := r.db.QueryRow(
		`SELECT id, type, COALESCE(url, ''), path, file_count,
		        COALESCE(git_branch, ''), COALESCE(git_commit_hash, ''), COALESCE(git_commit_short, ''), COALESCE(git_remote_url, ''),
		        created_at
		 FROM sources WHERE path = $1 ORDER BY created_at DESC LIMIT 1`, path)
	var src model.Source
	err := row.Scan(&src.ID, &src.Type, &src.URL, &src.Path, &src.FileCount,
		&src.GitBranch, &src.GitCommitHash, &src.GitCommitShort, &src.GitRemoteURL,
		&src.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find source by path: %w", err)
	}
	return &src, nil
}

func (r *PostgresRepo) CreateAudit(audit *model.Audit) error {
	cfgStr := "{}"
	if audit.Config != nil {
		cfgStr = string(audit.Config)
	}
	scoresJSON, _ := json.Marshal(audit.Scores)
	_, err := r.db.Exec(
		`INSERT INTO audits (id, source_id, types, config, status, scores, webhook_url, degraded_reason, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		audit.ID, audit.SourceID, pq.Array(audit.Types), cfgStr, string(audit.Status), string(scoresJSON), audit.WebhookURL, audit.DegradedReason, audit.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func (r *PostgresRepo) GetAudit(id string) (*model.Audit, error) {
	row := r.db.QueryRow(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, COALESCE(a.scores, '{}'), COALESCE(a.webhook_url, ''), COALESCE(a.degraded_reason, ''), a.created_at, a.completed_at
		 FROM audits a LEFT JOIN sources s ON a.source_id = s.id WHERE a.id = $1`, id)
	var audit model.Audit
	var cfgStr, scoresStr string
	var completedAt sql.NullTime
	err := row.Scan(&audit.ID, &audit.SourceID, &audit.SourcePath, pq.Array(&audit.Types), &cfgStr, &audit.Status, &scoresStr, &audit.WebhookURL, &audit.DegradedReason, &audit.CreatedAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan audit: %w", err)
	}
	audit.Config = json.RawMessage(cfgStr)
	audit.Scores = map[string]int{}
	_ = json.Unmarshal([]byte(scoresStr), &audit.Scores)
	if completedAt.Valid {
		audit.CompletedAt = &completedAt.Time
	}
	audit.Findings, _ = r.getFindings(audit.ID)
	audit.FindingsCount = len(audit.Findings)
	return &audit, nil
}

func (r *PostgresRepo) UpdateAudit(audit *model.Audit) error {
	scoresJSON, _ := json.Marshal(audit.Scores)
	var completedAt *time.Time
	if audit.CompletedAt != nil {
		completedAt = audit.CompletedAt
	}
	_, err := r.db.Exec(
		`UPDATE audits SET status = $1, scores = $2, completed_at = $3, degraded_reason = $4 WHERE id = $5`,
		string(audit.Status), string(scoresJSON), completedAt, audit.DegradedReason, audit.ID,
	)
	if err != nil {
		return fmt.Errorf("update audit: %w", err)
	}
	return nil
}

func (r *PostgresRepo) SaveFindings(auditID string, findings []model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	const cols = 19   // +6 columns for validation (feature 0045)
	valueStrings := make([]string, 0, len(findings))
	valueArgs := make([]interface{}, 0, len(findings)*cols)
	for i, f := range findings {
		base := i * cols
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, "+
				"$%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6,
			base+7, base+8, base+9, base+10, base+11, base+12, base+13,
			base+14, base+15, base+16, base+17, base+18, base+19,
		))
		refsJSON, _ := json.Marshal(f.References)
		var validationJSON interface{}
		if f.Validation != nil {
			b, _ := json.Marshal(f.Validation)
			validationJSON = string(b)
		}
		var validationStatus interface{}
		if f.ValidationStatus != "" {
			validationStatus = f.ValidationStatus
		}
		var validationConfidence interface{}
		if f.ValidationConfidence != 0 {
			validationConfidence = f.ValidationConfidence
		}
		var rolledUpInto interface{}
		if f.RolledUpInto != "" {
			rolledUpInto = f.RolledUpInto
		}
		valueArgs = append(valueArgs,
			f.ID, auditID, f.AgentType, string(f.Severity),
			f.Category, f.Title, f.Description, f.FilePath,
			f.LineStart, f.LineEnd, f.Recommendation, string(refsJSON), f.Fingerprint,
			validationStatus, validationConfidence, validationJSON,
			f.IsRollup, rolledUpInto, f.InstanceCount,
		)
	}
	stmt := fmt.Sprintf(
		`INSERT INTO findings (
			id, audit_id, agent_type, severity, category, title, description,
			file_path, line_start, line_end, recommendation, refs, fingerprint,
			validation_status, validation_confidence, validation,
			is_rollup, rolled_up_into, instance_count
		) VALUES %s ON CONFLICT DO NOTHING`,
		strings.Join(valueStrings, ","),
	)
	_, err := r.db.Exec(stmt, valueArgs...)
	if err != nil {
		return fmt.Errorf("insert findings: %w", err)
	}
	return nil
}

func (r *PostgresRepo) ListAudits(limit, offset int) ([]model.Audit, error) {
	if limit <= 0 {
		limit = 20
	}
	// Pre-limit audits, THEN aggregate counts via index scans on the page.
	// The original GROUP BY over LEFT JOINs of findings + prove_results
	// fully materialized those joins for every audit before the LIMIT
	// kicked in — cost grew with table size, not page size. The CTE form
	// is O(page * log N) on idx_findings_audit + idx_prove_results_audit.
	rows, err := r.db.Query(
		`WITH limited_audits AS (
			SELECT a.id, a.source_id, COALESCE(s.path, '') AS source_path, a.types, a.config, a.status,
			       COALESCE(a.scores, '{}') AS scores, a.created_at, a.completed_at
			FROM audits a
			LEFT JOIN sources s ON a.source_id = s.id
			ORDER BY a.created_at DESC
			LIMIT $1 OFFSET $2
		)
		SELECT la.id, la.source_id, la.source_path, la.types, la.config, la.status, la.scores,
			la.created_at, la.completed_at,
			(SELECT COUNT(*) FROM findings WHERE audit_id = la.id::text) AS findings_count,
			(SELECT COUNT(*) FROM prove_results WHERE audit_id = la.id::text) AS prove_count
		FROM limited_audits la
		ORDER BY la.created_at DESC`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audits: %w", err)
	}
	defer rows.Close()
	var audits []model.Audit
	for rows.Next() {
		var a model.Audit
		var cfgStr, scoresStr string
		var completedAt sql.NullTime
		err := rows.Scan(&a.ID, &a.SourceID, &a.SourcePath, pq.Array(&a.Types), &cfgStr, &a.Status, &scoresStr, &a.CreatedAt, &completedAt, &a.FindingsCount, &a.ProveCount)
		if err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		a.Config = json.RawMessage(cfgStr)
		a.Scores = map[string]int{}
		_ = json.Unmarshal([]byte(scoresStr), &a.Scores)
		if completedAt.Valid {
			a.CompletedAt = &completedAt.Time
		}
		audits = append(audits, a)
	}
	return audits, rows.Err()
}

func (r *PostgresRepo) GetStats() (*model.DashboardStats, error) {
	stats := &model.DashboardStats{}
	var avgScore sql.NullFloat64
	err := r.db.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM audits),
			(SELECT COUNT(*) FROM findings),
			(SELECT COUNT(*) FROM findings WHERE severity = 'critical'),
			COALESCE((SELECT AVG(score_val) FROM (
				SELECT (jsonb_each_text(scores)).value::int AS score_val
				FROM audits WHERE status = 'completed' AND scores != '{}'
			) sub), 0)
	`).Scan(&stats.AuditsRun, &stats.TotalFindings, &stats.CriticalIssues, &avgScore)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}
	if avgScore.Valid {
		stats.AverageScore = int(avgScore.Float64)
	}
	if err := scanProveStats(r.db, stats); err != nil {
		return nil, err
	}
	return stats, nil
}

func (r *PostgresRepo) GetLatestCompletedAudit(sourceID string, types []string) (*model.Audit, error) {
	row := r.db.QueryRow(`
		SELECT id, source_id, types, config, status, COALESCE(scores, '{}'), created_at, completed_at
		FROM audits
		WHERE source_id = $1 AND status = 'completed' AND types @> $2 AND types <@ $2
		ORDER BY completed_at DESC
		LIMIT 1`,
		sourceID, pq.Array(types),
	)
	var audit model.Audit
	var cfgStr, scoresStr string
	var completedAt sql.NullTime
	err := row.Scan(&audit.ID, &audit.SourceID, pq.Array(&audit.Types), &cfgStr, &audit.Status, &scoresStr, &audit.CreatedAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest completed audit: %w", err)
	}
	audit.Config = json.RawMessage(cfgStr)
	audit.Scores = map[string]int{}
	_ = json.Unmarshal([]byte(scoresStr), &audit.Scores)
	if completedAt.Valid {
		audit.CompletedAt = &completedAt.Time
	}
	audit.Findings, _ = r.getFindings(audit.ID)
	audit.FindingsCount = len(audit.Findings)
	return &audit, nil
}

func (r *PostgresRepo) GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error) {
	row := r.db.QueryRow(`
		SELECT id, source_id, types, config, status, COALESCE(scores, '{}'), created_at, completed_at
		FROM audits
		WHERE source_id = $1 AND status = 'completed' AND id != $2 AND types @> $3 AND types <@ $3
		ORDER BY completed_at DESC
		LIMIT 1`,
		sourceID, excludeAuditID, pq.Array(types),
	)
	var audit model.Audit
	var cfgStr, scoresStr string
	var completedAt sql.NullTime
	err := row.Scan(&audit.ID, &audit.SourceID, pq.Array(&audit.Types), &cfgStr, &audit.Status, &scoresStr, &audit.CreatedAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get previous completed audit: %w", err)
	}
	audit.Config = json.RawMessage(cfgStr)
	audit.Scores = map[string]int{}
	_ = json.Unmarshal([]byte(scoresStr), &audit.Scores)
	if completedAt.Valid {
		audit.CompletedAt = &completedAt.Time
	}
	audit.Findings, _ = r.getFindings(audit.ID)
	audit.FindingsCount = len(audit.Findings)
	return &audit, nil
}

func (r *PostgresRepo) ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error) {
	if limit <= 0 {
		limit = 20
	}
	// CTE pre-limits to the page before per-row count subqueries (same
	// rationale as ListAudits). Also returns prove_count so the handler
	// doesn't need a per-audit enrichProveCount round-trip.
	rows, err := r.db.Query(
		`WITH limited_audits AS (
			SELECT a.id, a.source_id, s.path AS source_path, a.types, a.config, a.status,
			       COALESCE(a.scores, '{}') AS scores, a.created_at, a.completed_at
			FROM audits a
			JOIN sources s ON a.source_id = s.id
			WHERE s.path = $1
			ORDER BY a.created_at DESC
			LIMIT $2 OFFSET $3
		)
		SELECT la.id, la.source_id, la.source_path, la.types, la.config, la.status, la.scores,
			la.created_at, la.completed_at,
			(SELECT COUNT(*) FROM findings WHERE audit_id = la.id::text) AS findings_count,
			(SELECT COUNT(*) FROM prove_results WHERE audit_id = la.id::text) AS prove_count
		FROM limited_audits la
		ORDER BY la.created_at DESC`,
		sourcePath, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audits by source path: %w", err)
	}
	defer rows.Close()
	var audits []model.Audit
	for rows.Next() {
		var a model.Audit
		var cfgStr, scoresStr string
		var completedAt sql.NullTime
		err := rows.Scan(&a.ID, &a.SourceID, &a.SourcePath, pq.Array(&a.Types), &cfgStr, &a.Status, &scoresStr, &a.CreatedAt, &completedAt, &a.FindingsCount, &a.ProveCount)
		if err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		a.Config = json.RawMessage(cfgStr)
		a.Scores = map[string]int{}
		_ = json.Unmarshal([]byte(scoresStr), &a.Scores)
		if completedAt.Valid {
			a.CompletedAt = &completedAt.Time
		}
		audits = append(audits, a)
	}
	return audits, rows.Err()
}

func (r *PostgresRepo) getFindings(auditID string) ([]model.Finding, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, agent_type, severity, category, title, description,
		        file_path, line_start, line_end, recommendation, refs,
		        COALESCE(fingerprint, ''),
		        COALESCE(validation_status, ''),
		        COALESCE(validation_confidence, 0),
		        COALESCE(validation, ''),
		        COALESCE(is_rollup, false),
		        COALESCE(rolled_up_into, ''),
		        COALESCE(instance_count, 1)
		 FROM findings WHERE audit_id = $1`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	// Pre-size to a typical audit-page size to avoid log-N reallocations
	// for the common case (most audits produce 10s-100s of findings).
	findings := make([]model.Finding, 0, 64)
	for rows.Next() {
		var f model.Finding
		var refsStr, validationStr string
		err := rows.Scan(&f.ID, &f.AuditID, &f.AgentType, &f.Severity, &f.Category,
			&f.Title, &f.Description, &f.FilePath, &f.LineStart, &f.LineEnd,
			&f.Recommendation, &refsStr, &f.Fingerprint,
			&f.ValidationStatus, &f.ValidationConfidence, &validationStr,
			&f.IsRollup, &f.RolledUpInto, &f.InstanceCount)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		_ = json.Unmarshal([]byte(refsStr), &f.References)
		if validationStr != "" {
			_ = json.Unmarshal([]byte(validationStr), &f.Validation)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
