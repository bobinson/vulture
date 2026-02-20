package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"

	_ "modernc.org/sqlite"
)

type SQLiteRepo struct {
	db *sql.DB
}

func NewSQLiteRepo(dbPath string) (*SQLiteRepo, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := configureSQLite(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &SQLiteRepo{db: db}, nil
}

func configureSQLite(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=30000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sources (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			url TEXT,
			path TEXT NOT NULL,
			file_count INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS audits (
			id TEXT PRIMARY KEY,
			source_id TEXT NOT NULL,
			types TEXT NOT NULL,
			config TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'pending',
			scores TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL,
			completed_at TEXT,
			FOREIGN KEY (source_id) REFERENCES sources(id)
		);
		CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			audit_id TEXT NOT NULL,
			agent_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			file_path TEXT NOT NULL,
			line_start INTEGER NOT NULL DEFAULT 0,
			line_end INTEGER NOT NULL DEFAULT 0,
			recommendation TEXT NOT NULL DEFAULT '',
			refs TEXT NOT NULL DEFAULT '[]',
			FOREIGN KEY (audit_id) REFERENCES audits(id)
		);
		CREATE TABLE IF NOT EXISTS teams (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin',
			team_id TEXT DEFAULT '',
			created_at TEXT NOT NULL,
			last_login_at TEXT,
			FOREIGN KEY (team_id) REFERENCES teams(id)
		);
		CREATE TABLE IF NOT EXISTS finding_lineage (
			id TEXT PRIMARY KEY,
			fingerprint TEXT NOT NULL,
			source_path TEXT NOT NULL,
			agent_type TEXT NOT NULL,
			current_status TEXT NOT NULL DEFAULT 'open',
			notes TEXT,
			ticket_url TEXT,
			first_audit_id TEXT NOT NULL REFERENCES audits(id),
			first_found_at TEXT NOT NULL,
			first_commit TEXT,
			latest_audit_id TEXT REFERENCES audits(id),
			latest_found_at TEXT,
			latest_commit TEXT,
			fixed_audit_id TEXT REFERENCES audits(id),
			fixed_at TEXT,
			fixed_commit TEXT,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			file_path TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE (fingerprint, source_path, agent_type)
		);
		CREATE TABLE IF NOT EXISTS lineage_events (
			id TEXT PRIMARY KEY,
			lineage_id TEXT NOT NULL REFERENCES finding_lineage(id) ON DELETE CASCADE,
			event_type TEXT NOT NULL,
			audit_id TEXT REFERENCES audits(id),
			git_commit TEXT,
			git_branch TEXT,
			old_status TEXT,
			new_status TEXT,
			notes TEXT,
			created_at TEXT NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	migrateAddColumns(db)
	return nil
}

func migrateAddColumns(db *sql.DB) {
	// Add git columns to sources (swallow errors if already exist)
	for _, col := range []string{
		"ALTER TABLE sources ADD COLUMN git_branch TEXT",
		"ALTER TABLE sources ADD COLUMN git_commit_hash TEXT",
		"ALTER TABLE sources ADD COLUMN git_commit_short TEXT",
		"ALTER TABLE sources ADD COLUMN git_remote_url TEXT",
		"ALTER TABLE findings ADD COLUMN fingerprint TEXT",
	} {
		_, _ = db.Exec(col)
	}
}

func (r *SQLiteRepo) Close() error {
	return r.db.Close()
}

func (r *SQLiteRepo) DB() *sql.DB {
	return r.db
}

func (r *SQLiteRepo) CreateSource(src *model.Source) error {
	_, err := r.db.Exec(
		`INSERT INTO sources (id, type, url, path, file_count, git_branch, git_commit_hash, git_commit_short, git_remote_url, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		src.ID, string(src.Type), src.URL, src.Path, src.FileCount,
		src.GitBranch, src.GitCommitHash, src.GitCommitShort, src.GitRemoteURL,
		src.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert source: %w", err)
	}
	return nil
}

func (r *SQLiteRepo) UpdateSourceGitInfo(id string, branch, commitHash, commitShort, remoteURL string) error {
	_, err := r.db.Exec(
		`UPDATE sources SET git_branch = ?, git_commit_hash = ?, git_commit_short = ?, git_remote_url = ? WHERE id = ?`,
		branch, commitHash, commitShort, remoteURL, id,
	)
	if err != nil {
		return fmt.Errorf("update source git info: %w", err)
	}
	return nil
}

func (r *SQLiteRepo) GetSource(id string) (*model.Source, error) {
	row := r.db.QueryRow(
		`SELECT id, type, COALESCE(url, ''), path, file_count,
		        COALESCE(git_branch, ''), COALESCE(git_commit_hash, ''), COALESCE(git_commit_short, ''), COALESCE(git_remote_url, ''),
		        created_at
		 FROM sources WHERE id = ?`, id)
	var src model.Source
	var createdAt string
	err := row.Scan(&src.ID, &src.Type, &src.URL, &src.Path, &src.FileCount,
		&src.GitBranch, &src.GitCommitHash, &src.GitCommitShort, &src.GitRemoteURL,
		&createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan source: %w", err)
	}
	src.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &src, nil
}

func (r *SQLiteRepo) FindSourceByPath(path string) (*model.Source, error) {
	row := r.db.QueryRow(
		`SELECT id, type, COALESCE(url, ''), path, file_count,
		        COALESCE(git_branch, ''), COALESCE(git_commit_hash, ''), COALESCE(git_commit_short, ''), COALESCE(git_remote_url, ''),
		        created_at
		 FROM sources WHERE path = ? ORDER BY created_at DESC LIMIT 1`, path)
	var src model.Source
	var createdAt string
	err := row.Scan(&src.ID, &src.Type, &src.URL, &src.Path, &src.FileCount,
		&src.GitBranch, &src.GitCommitHash, &src.GitCommitShort, &src.GitRemoteURL,
		&createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find source by path: %w", err)
	}
	src.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &src, nil
}

func (r *SQLiteRepo) CreateAudit(audit *model.Audit) error {
	typesJSON, _ := json.Marshal(audit.Types)
	cfgStr := "{}"
	if audit.Config != nil {
		cfgStr = string(audit.Config)
	}
	scoresJSON, _ := json.Marshal(audit.Scores)
	_, err := r.db.Exec(
		`INSERT INTO audits (id, source_id, types, config, status, scores, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		audit.ID, audit.SourceID, string(typesJSON), cfgStr, string(audit.Status), string(scoresJSON), audit.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func (r *SQLiteRepo) GetAudit(id string) (*model.Audit, error) {
	row := r.db.QueryRow(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, a.scores, a.created_at, a.completed_at
		 FROM audits a LEFT JOIN sources s ON a.source_id = s.id WHERE a.id = ?`, id)
	var audit model.Audit
	var typesStr, cfgStr, scoresStr, createdAt string
	var completedAt sql.NullString
	err := row.Scan(&audit.ID, &audit.SourceID, &audit.SourcePath, &typesStr, &cfgStr, &audit.Status, &scoresStr, &createdAt, &completedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan audit: %w", err)
	}
	_ = json.Unmarshal([]byte(typesStr), &audit.Types)
	audit.Config = json.RawMessage(cfgStr)
	audit.Scores = map[string]int{}
	_ = json.Unmarshal([]byte(scoresStr), &audit.Scores)
	audit.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339, completedAt.String)
		audit.CompletedAt = &t
	}
	audit.Findings, _ = r.getFindings(id)
	audit.FindingsCount = len(audit.Findings)
	return &audit, nil
}

func (r *SQLiteRepo) UpdateAudit(audit *model.Audit) error {
	scoresJSON, _ := json.Marshal(audit.Scores)
	var completedAt *string
	if audit.CompletedAt != nil {
		s := audit.CompletedAt.Format(time.RFC3339)
		completedAt = &s
	}
	_, err := r.db.Exec(
		`UPDATE audits SET status = ?, scores = ?, completed_at = ? WHERE id = ?`,
		string(audit.Status), string(scoresJSON), completedAt, audit.ID,
	)
	if err != nil {
		return fmt.Errorf("update audit: %w", err)
	}
	return nil
}

func (r *SQLiteRepo) SaveFindings(auditID string, findings []model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	valueStrings := make([]string, 0, len(findings))
	valueArgs := make([]interface{}, 0, len(findings)*13)
	for _, f := range findings {
		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		refsJSON, _ := json.Marshal(f.References)
		valueArgs = append(valueArgs, f.ID, auditID, f.AgentType, string(f.Severity),
			f.Category, f.Title, f.Description, f.FilePath,
			f.LineStart, f.LineEnd, f.Recommendation, string(refsJSON), f.Fingerprint)
	}
	stmt := fmt.Sprintf(
		`INSERT INTO findings (id, audit_id, agent_type, severity, category, title, description, file_path, line_start, line_end, recommendation, refs, fingerprint) VALUES %s`,
		strings.Join(valueStrings, ","),
	)
	_, err := r.db.Exec(stmt, valueArgs...)
	if err != nil {
		return fmt.Errorf("insert findings: %w", err)
	}
	return nil
}

func (r *SQLiteRepo) ListAudits(limit, offset int) ([]model.Audit, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, a.scores, a.created_at, a.completed_at,
			(SELECT COUNT(*) FROM findings f WHERE f.audit_id = a.id) AS findings_count
		FROM audits a
		LEFT JOIN sources s ON a.source_id = s.id
		ORDER BY a.created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list audits: %w", err)
	}
	defer rows.Close()
	var audits []model.Audit
	for rows.Next() {
		var a model.Audit
		var typesStr, cfgStr, scoresStr, createdAt string
		var completedAt sql.NullString
		err := rows.Scan(&a.ID, &a.SourceID, &a.SourcePath, &typesStr, &cfgStr, &a.Status, &scoresStr, &createdAt, &completedAt, &a.FindingsCount)
		if err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		_ = json.Unmarshal([]byte(typesStr), &a.Types)
		a.Config = json.RawMessage(cfgStr)
		a.Scores = map[string]int{}
		_ = json.Unmarshal([]byte(scoresStr), &a.Scores)
		a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			a.CompletedAt = &t
		}
		audits = append(audits, a)
	}
	return audits, rows.Err()
}

func (r *SQLiteRepo) GetStats() (*model.DashboardStats, error) {
	stats := &model.DashboardStats{}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM audits`).Scan(&stats.AuditsRun); err != nil {
		return nil, fmt.Errorf("count audits: %w", err)
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&stats.TotalFindings); err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE severity = 'critical'`).Scan(&stats.CriticalIssues); err != nil {
		return nil, fmt.Errorf("count critical: %w", err)
	}
	stats.AverageScore = r.computeAvgScore()
	return stats, nil
}

func (r *SQLiteRepo) computeAvgScore() int {
	rows, err := r.db.Query(`SELECT scores FROM audits WHERE status = 'completed' AND scores != '{}'`)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var total, count int
	for rows.Next() {
		var scoresStr string
		if err := rows.Scan(&scoresStr); err != nil {
			continue
		}
		total, count = accumulateScores(scoresStr, total, count)
	}
	if count == 0 {
		return 0
	}
	return total / count
}

func accumulateScores(scoresStr string, total, count int) (int, int) {
	var scores map[string]int
	if json.Unmarshal([]byte(scoresStr), &scores) != nil {
		return total, count
	}
	for _, v := range scores {
		total += v
		count++
	}
	return total, count
}

func (r *SQLiteRepo) GetLatestCompletedAudit(sourceID string, types []string) (*model.Audit, error) {
	rows, err := r.db.Query(
		`SELECT id, source_id, types, config, status, scores, created_at, completed_at
		 FROM audits WHERE source_id = ? AND status = 'completed'
		 ORDER BY created_at DESC LIMIT 10`,
		sourceID,
	)
	if err != nil {
		return nil, fmt.Errorf("get latest completed audit: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a model.Audit
		var typesStr, cfgStr, scoresStr, createdAt string
		var completedAt sql.NullString
		err := rows.Scan(&a.ID, &a.SourceID, &typesStr, &cfgStr, &a.Status, &scoresStr, &createdAt, &completedAt)
		if err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(typesStr), &a.Types)
		if !typesMatch(a.Types, types) {
			continue
		}
		a.Config = json.RawMessage(cfgStr)
		a.Scores = map[string]int{}
		_ = json.Unmarshal([]byte(scoresStr), &a.Scores)
		a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			a.CompletedAt = &t
		}
		a.Findings, _ = r.getFindings(a.ID)
		a.FindingsCount = len(a.Findings)
		return &a, nil
	}
	return nil, nil
}

func typesMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, t := range a {
		set[t] = true
	}
	for _, t := range b {
		if !set[t] {
			return false
		}
	}
	return true
}

func (r *SQLiteRepo) getFindings(auditID string) ([]model.Finding, error) {
	rows, err := r.db.Query(
		`SELECT id, audit_id, agent_type, severity, category, title, description, file_path, line_start, line_end, recommendation, refs, COALESCE(fingerprint, '') FROM findings WHERE audit_id = ?`,
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
