package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"

	"github.com/lib/pq"
)

type PostgresRepo struct {
	db *sql.DB
}

func NewPostgresRepo(dsn string) (*PostgresRepo, error) {
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
		`INSERT INTO audits (id, source_id, types, config, status, scores, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		audit.ID, audit.SourceID, pq.Array(audit.Types), cfgStr, string(audit.Status), string(scoresJSON), audit.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func (r *PostgresRepo) GetAudit(id string) (*model.Audit, error) {
	row := r.db.QueryRow(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, COALESCE(a.scores, '{}'), a.created_at, a.completed_at
		 FROM audits a LEFT JOIN sources s ON a.source_id = s.id WHERE a.id = $1`, id)
	var audit model.Audit
	var cfgStr, scoresStr string
	var completedAt sql.NullTime
	err := row.Scan(&audit.ID, &audit.SourceID, &audit.SourcePath, pq.Array(&audit.Types), &cfgStr, &audit.Status, &scoresStr, &audit.CreatedAt, &completedAt)
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
		`UPDATE audits SET status = $1, scores = $2, completed_at = $3 WHERE id = $4`,
		string(audit.Status), string(scoresJSON), completedAt, audit.ID,
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
	const cols = 13
	valueStrings := make([]string, 0, len(findings))
	valueArgs := make([]interface{}, 0, len(findings)*cols)
	for i, f := range findings {
		base := i * cols
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6,
			base+7, base+8, base+9, base+10, base+11, base+12, base+13,
		))
		refsJSON, _ := json.Marshal(f.References)
		valueArgs = append(valueArgs, f.ID, auditID, f.AgentType, string(f.Severity),
			f.Category, f.Title, f.Description, f.FilePath,
			f.LineStart, f.LineEnd, f.Recommendation, string(refsJSON), f.Fingerprint)
	}
	stmt := fmt.Sprintf(
		`INSERT INTO findings (id, audit_id, agent_type, severity, category, title, description, file_path, line_start, line_end, recommendation, refs, fingerprint) VALUES %s ON CONFLICT DO NOTHING`,
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
	rows, err := r.db.Query(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, COALESCE(a.scores, '{}'), a.created_at, a.completed_at,
			COUNT(DISTINCT f.id) AS findings_count,
			COUNT(DISTINCT pr.id) AS prove_count
		FROM audits a
		LEFT JOIN sources s ON a.source_id = s.id
		LEFT JOIN findings f ON f.audit_id = a.id::text
		LEFT JOIN prove_results pr ON pr.audit_id = a.id::text
		GROUP BY a.id, a.source_id, s.path, a.types, a.config, a.status, a.scores, a.created_at, a.completed_at
		ORDER BY a.created_at DESC LIMIT $1 OFFSET $2`,
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
	rows, err := r.db.Query(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, COALESCE(a.scores, '{}'), a.created_at, a.completed_at,
			COUNT(DISTINCT f.id) AS findings_count
		FROM audits a
		JOIN sources s ON a.source_id = s.id
		LEFT JOIN findings f ON f.audit_id = a.id::text
		WHERE s.path = $1
		GROUP BY a.id, a.source_id, s.path, a.types, a.config, a.status, a.scores, a.created_at, a.completed_at
		ORDER BY a.created_at DESC LIMIT $2 OFFSET $3`,
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
		err := rows.Scan(&a.ID, &a.SourceID, &a.SourcePath, pq.Array(&a.Types), &cfgStr, &a.Status, &scoresStr, &a.CreatedAt, &completedAt, &a.FindingsCount)
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
		`SELECT id, audit_id, agent_type, severity, category, title, description, file_path, line_start, line_end, recommendation, refs, COALESCE(fingerprint, '') FROM findings WHERE audit_id = $1`,
		auditID,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	var findings []model.Finding
	for rows.Next() {
		var f model.Finding
		var refsStr string
		err := rows.Scan(&f.ID, &f.AuditID, &f.AgentType, &f.Severity, &f.Category,
			&f.Title, &f.Description, &f.FilePath, &f.LineStart, &f.LineEnd,
			&f.Recommendation, &refsStr, &f.Fingerprint)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		_ = json.Unmarshal([]byte(refsStr), &f.References)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
