package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"

	_ "modernc.org/sqlite"
)

type SQLiteRepo struct {
	db              *sql.DB
	proveRepo       *SQLiteProveRepo
	stmtGetFindings *sql.Stmt
}

func NewSQLiteRepo(dbPath string) (*SQLiteRepo, error) {
	// PRAGMAs must be in the DSN — modernc.org/sqlite applies them per
	// connection. Setting them via db.Exec only affects the single
	// connection that ran the statement; subsequent pool connections
	// inherit SQLite defaults (no WAL, no busy_timeout) and concurrent
	// writers then hit `database is locked` under audit-time load.
	dsn := dbPath
	if !strings.Contains(dsn, "?") {
		dsn += "?"
	} else {
		dsn += "&"
	}
	dsn += "_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// WAL mode supports concurrent reads. Allow up to 4 connections for read
	// parallelism while SQLite serialises writes internally via busy_timeout.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := configureSQLite(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	repo := &SQLiteRepo{db: db, proveRepo: &SQLiteProveRepo{db: db}}
	repo.prepareStatements()
	return repo, nil
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
			-- 0036 Phase 3 (C2): default to 'member', NOT 'admin'.
			-- The Postgres migration already does this; the SQLite
			-- schema had drifted to 'admin' which silently promotes
			-- any future INSERT that elides the role column.
			role TEXT NOT NULL DEFAULT 'member'
				CHECK (role IN ('admin', 'member', 'viewer')),
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
	// Prove results table (verification outcomes)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS prove_results (
		id TEXT PRIMARY KEY,
		audit_id TEXT NOT NULL REFERENCES audits(id),
		finding_id TEXT NOT NULL,
		status TEXT NOT NULL,
		evidence TEXT NOT NULL DEFAULT '',
		iterations_used INTEGER NOT NULL DEFAULT 0,
		staging_url TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_prove_results_audit ON prove_results(audit_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_prove_results_finding ON prove_results(finding_id)`)
	_, _ = db.Exec(`ALTER TABLE prove_results ADD COLUMN fingerprint TEXT DEFAULT ''`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_prove_fingerprint ON prove_results(fingerprint)`)

	// Pipeline stages table (scan → discover → prove orchestration)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS pipelines (
		id TEXT PRIMARY KEY,
		target_url TEXT NOT NULL DEFAULT '',
		source_id TEXT DEFAULT '',
		stages TEXT NOT NULL DEFAULT '[]',
		config TEXT NOT NULL DEFAULT '{}',
		scan_audit_id TEXT DEFAULT '',
		discover_audit_id TEXT DEFAULT '',
		prove_audit_id TEXT DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TEXT NOT NULL,
		completed_at TEXT
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_pipelines_status ON pipelines(status)`)

	// Discover results table (endpoint discovery output)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS discover_results (
		id TEXT PRIMARY KEY,
		audit_id TEXT NOT NULL REFERENCES audits(id),
		target_url TEXT NOT NULL,
		site_map_json TEXT NOT NULL DEFAULT '{}',
		url_count INTEGER NOT NULL DEFAULT 0,
		api_count INTEGER NOT NULL DEFAULT 0,
		form_count INTEGER NOT NULL DEFAULT 0,
		technologies TEXT NOT NULL DEFAULT '[]',
		created_at TEXT NOT NULL
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_discover_results_audit ON discover_results(audit_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_discover_results_target ON discover_results(target_url)`)

	// Performance indexes for hot query paths
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_audits_source_status ON audits(source_id, status, created_at)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_sources_path ON sources(path)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_memories_path_agent ON audit_memories(codebase_path, agent_type)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_memory_edges_source ON memory_edges(source_id, target_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_lineage_fingerprint ON finding_lineage(fingerprint, source_path, agent_type)`)

	// Feature 0031: API keys table
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS api_keys (
		id          TEXT PRIMARY KEY,
		prefix      TEXT NOT NULL,
		hash        TEXT NOT NULL,
		name        TEXT NOT NULL,
		scopes      TEXT NOT NULL DEFAULT '["read","write"]',
		created_by  TEXT NOT NULL,
		created_at  TEXT NOT NULL,
		last_used_at TEXT,
		revoked_at  TEXT
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix) WHERE revoked_at IS NULL`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by)`)

	// Feature 0039: per-audit degraded-mode reason (LLM unreachable at submit time)
	_, _ = db.Exec(`ALTER TABLE audits ADD COLUMN degraded_reason TEXT NOT NULL DEFAULT ''`)

	// Feature 0031: webhook deliveries
	_, _ = db.Exec(`ALTER TABLE audits ADD COLUMN webhook_url TEXT`)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS audit_webhook_deliveries (
		id            TEXT PRIMARY KEY,
		audit_id      TEXT NOT NULL,
		url           TEXT NOT NULL,
		status        TEXT NOT NULL DEFAULT 'pending',
		attempts      INTEGER NOT NULL DEFAULT 0,
		last_error    TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL,
		delivered_at  TEXT
	)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_audit ON audit_webhook_deliveries(audit_id)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON audit_webhook_deliveries(status)`)

	// Feature 0033: finding reference numbers
	_, _ = db.Exec(`ALTER TABLE finding_lineage ADD COLUMN ref_number INTEGER`)
	// Backfill existing records. Use rowid for unique ordering (avoids duplicates
	// when multiple records share the same created_at timestamp).
	_, _ = db.Exec(`
		UPDATE finding_lineage SET ref_number = (
			SELECT COUNT(*) FROM finding_lineage AS fl2
			WHERE fl2.rowid < finding_lineage.rowid
		) + 1 WHERE ref_number IS NULL
	`)

	// Feature 0045: validation phase columns.
	_, _ = db.Exec(`ALTER TABLE findings ADD COLUMN validation_status TEXT`)
	_, _ = db.Exec(`ALTER TABLE findings ADD COLUMN validation_confidence REAL`)
	_, _ = db.Exec(`ALTER TABLE findings ADD COLUMN validation TEXT`)
	_, _ = db.Exec(`ALTER TABLE findings ADD COLUMN is_rollup BOOLEAN DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE findings ADD COLUMN rolled_up_into TEXT`)
	_, _ = db.Exec(`ALTER TABLE findings ADD COLUMN instance_count INTEGER DEFAULT 1`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_validation_status
		ON findings(audit_id, validation_status)`)
	_, _ = db.Exec(`ALTER TABLE audit_memories ADD COLUMN user_label TEXT`)
	_, _ = db.Exec(`ALTER TABLE audit_memories ADD COLUMN labelled_by TEXT`)
	_, _ = db.Exec(`ALTER TABLE audit_memories ADD COLUMN labelled_at TIMESTAMP`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_memories_label
		ON audit_memories(user_label)`)
}

// prepareStatements pre-compiles frequently executed queries for reuse.
func (r *SQLiteRepo) prepareStatements() {
	const getFindingsSQL = `SELECT id, audit_id, agent_type, severity, category, title, description,
		file_path, line_start, line_end, recommendation, refs,
		COALESCE(fingerprint, ''),
		COALESCE(validation_status, ''),
		COALESCE(validation_confidence, 0),
		COALESCE(validation, ''),
		COALESCE(is_rollup, 0),
		COALESCE(rolled_up_into, ''),
		COALESCE(instance_count, 1)
		FROM findings WHERE audit_id = ?`
	stmt, err := r.db.Prepare(getFindingsSQL)
	if err != nil {
		log.Printf("[sqlite] prepare getFindings failed (will use raw query): %v", err)
		return
	}
	r.stmtGetFindings = stmt
}

func (r *SQLiteRepo) Close() error {
	if r.stmtGetFindings != nil {
		r.stmtGetFindings.Close()
	}
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
		`INSERT INTO audits (id, source_id, types, config, status, scores, webhook_url, degraded_reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		audit.ID, audit.SourceID, string(typesJSON), cfgStr, string(audit.Status), string(scoresJSON), audit.WebhookURL, audit.DegradedReason, audit.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func (r *SQLiteRepo) GetAudit(id string) (*model.Audit, error) {
	row := r.db.QueryRow(
		`SELECT a.id, a.source_id, COALESCE(s.path, ''), a.types, a.config, a.status, a.scores, COALESCE(a.webhook_url, ''), COALESCE(a.degraded_reason, ''), a.created_at, a.completed_at
		 FROM audits a LEFT JOIN sources s ON a.source_id = s.id WHERE a.id = ?`, id)
	var audit model.Audit
	var typesStr, cfgStr, scoresStr, createdAt string
	var completedAt sql.NullString
	err := row.Scan(&audit.ID, &audit.SourceID, &audit.SourcePath, &typesStr, &cfgStr, &audit.Status, &scoresStr, &audit.WebhookURL, &audit.DegradedReason, &createdAt, &completedAt)
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
	audit.ProveResults, _ = r.proveRepo.GetProveResults(id)
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
		`UPDATE audits SET status = ?, scores = ?, completed_at = ?, degraded_reason = ? WHERE id = ?`,
		string(audit.Status), string(scoresJSON), completedAt, audit.DegradedReason, audit.ID,
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
	valueArgs := make([]interface{}, 0, len(findings)*19)
	for _, f := range findings {
		valueStrings = append(valueStrings,
			"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		refsJSON, _ := json.Marshal(f.References)
		var validationJSON string
		if f.Validation != nil {
			b, _ := json.Marshal(f.Validation)
			validationJSON = string(b)
		}
		valueArgs = append(valueArgs,
			f.ID, auditID, f.AgentType, string(f.Severity),
			f.Category, f.Title, f.Description, f.FilePath,
			f.LineStart, f.LineEnd, f.Recommendation, string(refsJSON), f.Fingerprint,
			// Validation (feature 0045) — all nullable; empty string + 0 are
			// stored when absent so the column query is uniform.
			nullableString(f.ValidationStatus),
			nullableFloat(f.ValidationConfidence),
			nullableString(validationJSON),
			f.IsRollup,
			nullableString(f.RolledUpInto),
			f.InstanceCount,
		)
	}
	stmt := fmt.Sprintf(
		`INSERT INTO findings (
			id, audit_id, agent_type, severity, category, title, description,
			file_path, line_start, line_end, recommendation, refs, fingerprint,
			validation_status, validation_confidence, validation,
			is_rollup, rolled_up_into, instance_count
		) VALUES %s`,
		strings.Join(valueStrings, ","),
	)
	_, err := r.db.Exec(stmt, valueArgs...)
	if err != nil {
		return fmt.Errorf("insert findings: %w", err)
	}
	return nil
}

// nullableString converts empty Go strings to SQL NULL.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableFloat converts 0.0 Go floats to SQL NULL.
func nullableFloat(f float64) interface{} {
	if f == 0 {
		return nil
	}
	return f
}

func (r *SQLiteRepo) ListAudits(limit, offset int) ([]model.Audit, error) {
	if limit <= 0 {
		limit = 20
	}
	// Pre-limit, then count via correlated subqueries on idx_findings_audit
	// and idx_prove_results_audit. See postgres_repo.go::ListAudits for the
	// full rationale.
	rows, err := r.db.Query(
		`WITH limited_audits AS (
			SELECT a.id, a.source_id, COALESCE(s.path, '') AS source_path, a.types, a.config, a.status,
			       a.scores, a.created_at, a.completed_at
			FROM audits a
			LEFT JOIN sources s ON a.source_id = s.id
			ORDER BY a.created_at DESC
			LIMIT ? OFFSET ?
		)
		SELECT la.id, la.source_id, la.source_path, la.types, la.config, la.status, la.scores,
			la.created_at, la.completed_at,
			(SELECT COUNT(*) FROM findings WHERE audit_id = la.id) AS findings_count,
			(SELECT COUNT(*) FROM prove_results WHERE audit_id = la.id) AS prove_count
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
		var typesStr, cfgStr, scoresStr, createdAt string
		var completedAt sql.NullString
		err := rows.Scan(&a.ID, &a.SourceID, &a.SourcePath, &typesStr, &cfgStr, &a.Status, &scoresStr, &createdAt, &completedAt, &a.FindingsCount, &a.ProveCount)
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
	if err := scanProveStats(r.db, stats); err != nil {
		return nil, err
	}
	return stats, nil
}

func (r *SQLiteRepo) computeAvgScore() int {
	rows, err := r.db.Query(`SELECT scores FROM audits WHERE status = 'completed' AND scores != '{}' ORDER BY created_at DESC LIMIT 100`)
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
	// Collect candidates first, then close rows before nested getFindings query.
	// SQLite's connection pool (MaxOpenConns=4 in WAL mode) can exhaust all
	// connections if rows.Scan loops hold connections while getFindings opens another.
	type candidate struct {
		audit       model.Audit
		completedAt sql.NullString
	}
	rows, err := r.db.Query(
		`SELECT id, source_id, types, config, status, scores, created_at, completed_at
		 FROM audits WHERE source_id = ? AND status = 'completed'
		 ORDER BY created_at DESC LIMIT 10`,
		sourceID,
	)
	if err != nil {
		return nil, fmt.Errorf("get latest completed audit: %w", err)
	}
	var match *candidate
	for rows.Next() {
		var c candidate
		var typesStr, cfgStr, scoresStr, createdAt string
		err := rows.Scan(&c.audit.ID, &c.audit.SourceID, &typesStr, &cfgStr, &c.audit.Status, &scoresStr, &createdAt, &c.completedAt)
		if err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(typesStr), &c.audit.Types)
		if !typesMatch(c.audit.Types, types) {
			continue
		}
		c.audit.Config = json.RawMessage(cfgStr)
		c.audit.Scores = map[string]int{}
		_ = json.Unmarshal([]byte(scoresStr), &c.audit.Scores)
		c.audit.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if c.completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, c.completedAt.String)
			c.audit.CompletedAt = &t
		}
		match = &c
		break
	}
	rows.Close()
	if match == nil {
		return nil, nil
	}
	match.audit.Findings, _ = r.getFindings(match.audit.ID)
	match.audit.FindingsCount = len(match.audit.Findings)
	return &match.audit, nil
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

func (r *SQLiteRepo) GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error) {
	// Same candidate pattern as GetLatestCompletedAudit to avoid connection pool exhaustion.
	type candidate struct {
		audit       model.Audit
		completedAt sql.NullString
	}
	rows, err := r.db.Query(
		`SELECT id, source_id, types, config, status, scores, created_at, completed_at
		 FROM audits WHERE source_id = ? AND status = 'completed' AND id != ?
		 ORDER BY created_at DESC LIMIT 10`,
		sourceID, excludeAuditID,
	)
	if err != nil {
		return nil, fmt.Errorf("get previous completed audit: %w", err)
	}
	var match *candidate
	for rows.Next() {
		var c candidate
		var typesStr, cfgStr, scoresStr, createdAt string
		err := rows.Scan(&c.audit.ID, &c.audit.SourceID, &typesStr, &cfgStr, &c.audit.Status, &scoresStr, &createdAt, &c.completedAt)
		if err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(typesStr), &c.audit.Types)
		if !typesMatch(c.audit.Types, types) {
			continue
		}
		c.audit.Config = json.RawMessage(cfgStr)
		c.audit.Scores = map[string]int{}
		_ = json.Unmarshal([]byte(scoresStr), &c.audit.Scores)
		c.audit.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if c.completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, c.completedAt.String)
			c.audit.CompletedAt = &t
		}
		match = &c
		break
	}
	rows.Close()
	if match == nil {
		return nil, nil
	}
	match.audit.Findings, _ = r.getFindings(match.audit.ID)
	match.audit.FindingsCount = len(match.audit.Findings)
	return &match.audit, nil
}

func (r *SQLiteRepo) ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error) {
	if limit <= 0 {
		limit = 20
	}
	// CTE pre-limits to the page; correlated subqueries count via index.
	// Also returns prove_count so the handler can skip enrichProveCount
	// (which was an N+1 round-trip per audit).
	rows, err := r.db.Query(
		`WITH limited_audits AS (
			SELECT a.id, a.source_id, s.path AS source_path, a.types, a.config, a.status,
			       a.scores, a.created_at, a.completed_at
			FROM audits a
			JOIN sources s ON a.source_id = s.id
			WHERE s.path = ?
			ORDER BY a.created_at DESC
			LIMIT ? OFFSET ?
		)
		SELECT la.id, la.source_id, la.source_path, la.types, la.config, la.status, la.scores,
			la.created_at, la.completed_at,
			(SELECT COUNT(*) FROM findings WHERE audit_id = la.id) AS findings_count,
			(SELECT COUNT(*) FROM prove_results WHERE audit_id = la.id) AS prove_count
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
		var typesStr, cfgStr, scoresStr, createdAt string
		var completedAt sql.NullString
		err := rows.Scan(&a.ID, &a.SourceID, &a.SourcePath, &typesStr, &cfgStr, &a.Status, &scoresStr, &createdAt, &completedAt, &a.FindingsCount, &a.ProveCount)
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

func (r *SQLiteRepo) getFindings(auditID string) ([]model.Finding, error) {
	var rows *sql.Rows
	var err error
	if r.stmtGetFindings != nil {
		rows, err = r.stmtGetFindings.Query(auditID)
	} else {
		rows, err = r.db.Query(
			`SELECT id, audit_id, agent_type, severity, category, title, description,
			        file_path, line_start, line_end, recommendation, refs,
			        COALESCE(fingerprint, ''),
			        COALESCE(validation_status, ''),
			        COALESCE(validation_confidence, 0),
			        COALESCE(validation, ''),
			        COALESCE(is_rollup, 0),
			        COALESCE(rolled_up_into, ''),
			        COALESCE(instance_count, 1)
			 FROM findings WHERE audit_id = ?`,
			auditID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	// Pre-size: typical audits produce dozens of findings. 64 covers the
	// common case without over-allocating for tiny audits.
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

// Prove result methods are in sqlite_prove_repo.go (SQLiteProveRepo).
// SQLiteRepo delegates via r.proveRepo for internal use (e.g., GetAudit).
