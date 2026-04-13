package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// --- Issue #3: SQLite connection pool settings ---

func TestSQLiteConnectionPool(t *testing.T) {
	repo := newTestRepo(t)
	db := repo.DB()

	// MaxOpenConns should allow concurrent reads (>1)
	stats := db.Stats()
	// With MaxOpenConns(4), we should be able to open multiple connections
	if stats.MaxOpenConnections < 2 {
		t.Errorf("MaxOpenConns too low for concurrent reads: got %d, want >= 2", stats.MaxOpenConnections)
	}
	if stats.MaxOpenConnections > 10 {
		t.Errorf("MaxOpenConns too high, risk of SQLITE_BUSY: got %d, want <= 10", stats.MaxOpenConnections)
	}
}

func TestSQLiteConcurrentReads(t *testing.T) {
	repo := newTestRepo(t)

	// Setup: create source and several audits with findings
	src := &model.Source{
		ID: "src-conc", Type: model.SourceTypeLocal, Path: "/tmp/concurrent",
		FileCount: 5, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}
	for i := 0; i < 5; i++ {
		audit := &model.Audit{
			ID: fmt.Sprintf("conc-audit-%d", i), SourceID: "src-conc",
			Types: []string{"owasp"}, Config: json.RawMessage("{}"),
			Status: model.AuditStatusCompleted, Scores: map[string]int{"owasp": 80},
			CreatedAt: time.Now().UTC(),
		}
		if err := repo.CreateAudit(audit); err != nil {
			t.Fatalf("create audit %d: %v", i, err)
		}
		findings := []model.Finding{
			{
				ID: fmt.Sprintf("conc-f-%d", i), AuditID: audit.ID,
				AgentType: "owasp", Severity: model.SeverityHigh,
				Category: "injection", Title: fmt.Sprintf("Finding %d", i),
				Description: "desc", FilePath: "main.go",
			},
		}
		if err := repo.SaveFindings(audit.ID, findings); err != nil {
			t.Fatalf("save findings %d: %v", i, err)
		}
	}

	// Concurrent reads should not deadlock with MaxOpenConns > 1
	done := make(chan error, 3)
	go func() {
		_, err := repo.ListAudits(10, 0)
		done <- err
	}()
	go func() {
		_, err := repo.GetAudit("conc-audit-0")
		done <- err
	}()
	go func() {
		_, err := repo.GetStats()
		done <- err
	}()

	for i := 0; i < 3; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent read %d failed: %v", i, err)
		}
	}
}

// --- Issue #4: N+1 subqueries replaced with JOIN + GROUP BY ---

func TestListAuditsJoinCountsCorrect(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-join", Type: model.SourceTypeLocal, Path: "/tmp/join",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	// Create audit with known finding count
	audit := &model.Audit{
		ID: "join-audit-1", SourceID: "src-join", Types: []string{"owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	// Save 3 findings for this audit
	findings := make([]model.Finding, 3)
	for i := 0; i < 3; i++ {
		findings[i] = model.Finding{
			ID: fmt.Sprintf("jf-%d", i), AuditID: "join-audit-1",
			AgentType: "owasp", Severity: model.SeverityHigh,
			Category: "injection", Title: fmt.Sprintf("Join Finding %d", i),
			Description: "desc", FilePath: "main.go",
		}
	}
	if err := repo.SaveFindings("join-audit-1", findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	// Create audit with 0 findings
	audit2 := &model.Audit{
		ID: "join-audit-2", SourceID: "src-join", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC().Add(time.Second),
	}
	if err := repo.CreateAudit(audit2); err != nil {
		t.Fatalf("create audit2: %v", err)
	}

	// ListAudits should report correct counts via JOIN (not N+1 subqueries)
	audits, err := repo.ListAudits(10, 0)
	if err != nil {
		t.Fatalf("list audits: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("expected 2 audits, got %d", len(audits))
	}

	// Find each audit and check counts
	countsByID := map[string]int{}
	for _, a := range audits {
		countsByID[a.ID] = a.FindingsCount
	}
	if countsByID["join-audit-1"] != 3 {
		t.Errorf("expected 3 findings for join-audit-1, got %d", countsByID["join-audit-1"])
	}
	if countsByID["join-audit-2"] != 0 {
		t.Errorf("expected 0 findings for join-audit-2, got %d", countsByID["join-audit-2"])
	}
}

func TestListAuditsBySourcePathJoinCounts(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-sp", Type: model.SourceTypeLocal, Path: "/tmp/sp-test",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	audit := &model.Audit{
		ID: "sp-audit-1", SourceID: "src-sp", Types: []string{"owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	findings := []model.Finding{
		{ID: "spf-1", AuditID: "sp-audit-1", AgentType: "owasp", Severity: model.SeverityHigh, Category: "xss", Title: "XSS", Description: "d", FilePath: "web.js"},
		{ID: "spf-2", AuditID: "sp-audit-1", AgentType: "owasp", Severity: model.SeverityMedium, Category: "csrf", Title: "CSRF", Description: "d", FilePath: "form.js"},
	}
	if err := repo.SaveFindings("sp-audit-1", findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	audits, err := repo.ListAuditsBySourcePath("/tmp/sp-test", 10, 0)
	if err != nil {
		t.Fatalf("list by source path: %v", err)
	}
	if len(audits) != 1 {
		t.Fatalf("expected 1 audit, got %d", len(audits))
	}
	if audits[0].FindingsCount != 2 {
		t.Errorf("expected 2 findings, got %d", audits[0].FindingsCount)
	}
}

// --- Issue #5: Required indexes exist ---

func TestIndexesExist(t *testing.T) {
	repo := newTestRepo(t)
	db := repo.DB()

	// Core indexes on tables created by the main migration
	coreIndexes := []string{
		"idx_audits_source_status",
		"idx_sources_path",
		"idx_findings_audit",
		"idx_findings_file_path",
		"idx_lineage_fingerprint",
	}

	for _, idx := range coreIndexes {
		var name string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx,
		).Scan(&name)
		if err == sql.ErrNoRows {
			t.Errorf("missing required index: %s", idx)
		} else if err != nil {
			t.Errorf("error checking index %s: %v", idx, err)
		}
	}
}

func TestMemoryIndexesExistWhenTablesPresent(t *testing.T) {
	repo := newTestRepo(t)
	db := repo.DB()

	// Create the memory tables so indexes can be applied
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS audit_memories (
		id TEXT PRIMARY KEY,
		codebase_path TEXT NOT NULL DEFAULT '',
		agent_type TEXT NOT NULL DEFAULT ''
	)`)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS memory_edges (
		id TEXT PRIMARY KEY,
		source_id TEXT NOT NULL,
		target_id TEXT NOT NULL
	)`)

	// Re-run migrateAddColumns to apply memory indexes
	migrateAddColumns(db)

	memoryIndexes := []string{
		"idx_memories_path_agent",
		"idx_memory_edges_source",
	}
	for _, idx := range memoryIndexes {
		var name string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx,
		).Scan(&name)
		if err == sql.ErrNoRows {
			t.Errorf("missing memory index: %s", idx)
		} else if err != nil {
			t.Errorf("error checking index %s: %v", idx, err)
		}
	}
}

// --- Issue #39: computeAvgScore with LIMIT ---

func TestComputeAvgScoreWithLimit(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-avg", Type: model.SourceTypeLocal, Path: "/tmp/avg",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	// Create completed audits with scores
	for i := 0; i < 3; i++ {
		now := time.Now().UTC()
		audit := &model.Audit{
			ID: fmt.Sprintf("avg-audit-%d", i), SourceID: "src-avg",
			Types: []string{"owasp"}, Config: json.RawMessage("{}"),
			Status: model.AuditStatusCompleted,
			Scores: map[string]int{"owasp": 70 + i*10},
			CreatedAt: now, CompletedAt: &now,
		}
		if err := repo.CreateAudit(audit); err != nil {
			t.Fatalf("create audit %d: %v", i, err)
		}
		if err := repo.UpdateAudit(audit); err != nil {
			t.Fatalf("update audit %d: %v", i, err)
		}
	}

	score := repo.computeAvgScore()
	// Scores: 70, 80, 90 -> avg = 80
	if score != 80 {
		t.Errorf("expected avg score 80, got %d", score)
	}
}

// --- Issue #16: Prepared statements for hot queries ---

func TestPreparedStatementsGetFindings(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-ps", Type: model.SourceTypeLocal, Path: "/tmp/ps",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}
	audit := &model.Audit{
		ID: "ps-audit", SourceID: "src-ps", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	findings := []model.Finding{
		{ID: "psf-1", AuditID: "ps-audit", AgentType: "chaos", Severity: model.SeverityHigh, Category: "retry", Title: "No retry", Description: "d", FilePath: "svc.go"},
	}
	if err := repo.SaveFindings("ps-audit", findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	// Verify prepared statement is used (by calling getFindings multiple times)
	for i := 0; i < 3; i++ {
		got, err := repo.getFindings("ps-audit")
		if err != nil {
			t.Fatalf("getFindings call %d: %v", i, err)
		}
		if len(got) != 1 {
			t.Fatalf("call %d: expected 1 finding, got %d", i, len(got))
		}
	}

	// Verify stmtGetFindings field is non-nil (prepared statement exists)
	if repo.stmtGetFindings == nil {
		t.Error("expected stmtGetFindings to be prepared (non-nil)")
	}
}

// Verify that ListAudits with multiple audits having varying prove counts
// returns correct counts after the JOIN rewrite.
func TestListAuditsProveCount(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-prove", Type: model.SourceTypeLocal, Path: "/tmp/prove",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	audit := &model.Audit{
		ID: "prove-audit-1", SourceID: "src-prove", Types: []string{"owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	// Insert prove results directly
	for i := 0; i < 2; i++ {
		_, err := repo.db.Exec(
			`INSERT INTO prove_results (id, audit_id, finding_id, status, evidence, iterations_used, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("pr-%d", i), "prove-audit-1", fmt.Sprintf("f-%d", i),
			"verified", "evidence", 1, time.Now().UTC().Format(time.RFC3339),
		)
		if err != nil {
			t.Fatalf("insert prove result %d: %v", i, err)
		}
	}

	audits, err := repo.ListAudits(10, 0)
	if err != nil {
		t.Fatalf("list audits: %v", err)
	}
	if len(audits) != 1 {
		t.Fatalf("expected 1 audit, got %d", len(audits))
	}
	if audits[0].ProveCount != 2 {
		t.Errorf("expected prove_count=2, got %d", audits[0].ProveCount)
	}
}
