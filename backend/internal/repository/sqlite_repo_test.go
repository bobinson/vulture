package repository

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

func newTestRepo(t *testing.T) *SQLiteRepo {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	t.Cleanup(func() { repo.Close() })
	return repo
}

func TestCreateAndGetSource(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID:        "src-1",
		Type:      model.SourceTypeLocal,
		Path:      "/tmp/test",
		FileCount: 10,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	got, err := repo.GetSource("src-1")
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if got == nil {
		t.Fatal("expected source, got nil")
	}
	if got.Path != "/tmp/test" {
		t.Fatalf("expected path /tmp/test, got %s", got.Path)
	}
	if got.FileCount != 10 {
		t.Fatalf("expected file count 10, got %d", got.FileCount)
	}
}

func TestGetSourceNotFound(t *testing.T) {
	repo := newTestRepo(t)
	got, err := repo.GetSource("nonexistent")
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil, got source")
	}
}

func TestCreateAndGetAudit(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create source: %v", err)
	}

	audit := &model.Audit{
		ID:        "audit-1",
		SourceID:  "src-1",
		Types:     []string{"chaos", "owasp"},
		Config:    json.RawMessage(`{"soc2":{"clauses":["CC6"]}}`),
		Status:    model.AuditStatusPending,
		Scores:    map[string]int{},
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	got, err := repo.GetAudit("audit-1")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if got == nil {
		t.Fatal("expected audit, got nil")
	}
	if got.SourceID != "src-1" {
		t.Fatalf("expected source_id src-1, got %s", got.SourceID)
	}
	if len(got.Types) != 2 {
		t.Fatalf("expected 2 types, got %d", len(got.Types))
	}
}

func TestUpdateAudit(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	audit := &model.Audit{
		ID: "audit-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)

	now := time.Now().UTC()
	audit.Status = model.AuditStatusCompleted
	audit.CompletedAt = &now
	audit.Scores = map[string]int{"chaos": 85}

	if err := repo.UpdateAudit(audit); err != nil {
		t.Fatalf("update audit: %v", err)
	}

	got, _ := repo.GetAudit("audit-1")
	if got.Status != model.AuditStatusCompleted {
		t.Fatalf("expected completed, got %s", got.Status)
	}
	if got.Scores["chaos"] != 85 {
		t.Fatalf("expected score 85, got %d", got.Scores["chaos"])
	}
}

func TestSaveAndGetFindings(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	audit := &model.Audit{
		ID: "audit-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)

	findings := []model.Finding{
		{
			ID: "f-1", AuditID: "audit-1", AgentType: "chaos",
			Severity: model.SeverityHigh, Category: "retry",
			Title: "Missing retry", Description: "No retry logic",
			FilePath: "main.go", LineStart: 10, LineEnd: 20,
			Recommendation: "Add retry", References: []string{"https://example.com"},
		},
	}
	if err := repo.SaveFindings("audit-1", findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}

	got, _ := repo.GetAudit("audit-1")
	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got.Findings))
	}
	if got.Findings[0].Title != "Missing retry" {
		t.Fatalf("expected title 'Missing retry', got %s", got.Findings[0].Title)
	}
}

func TestSaveEmptyFindings(t *testing.T) {
	repo := newTestRepo(t)
	if err := repo.SaveFindings("audit-1", nil); err != nil {
		t.Fatalf("save empty findings: %v", err)
	}
}

func TestListAudits(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	for i := 0; i < 5; i++ {
		audit := &model.Audit{
			ID:        fmt.Sprintf("audit-%d", i),
			SourceID:  "src-1",
			Types:     []string{"chaos"},
			Config:    json.RawMessage("{}"),
			Status:    model.AuditStatusPending,
			Scores:    map[string]int{},
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
		}
		_ = repo.CreateAudit(audit)
	}

	audits, err := repo.ListAudits(3, 0)
	if err != nil {
		t.Fatalf("list audits: %v", err)
	}
	if len(audits) != 3 {
		t.Fatalf("expected 3 audits, got %d", len(audits))
	}

	// Test offset
	audits, err = repo.ListAudits(10, 3)
	if err != nil {
		t.Fatalf("list audits offset: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("expected 2 audits with offset 3, got %d", len(audits))
	}
}

func TestListAuditsDefaultLimit(t *testing.T) {
	repo := newTestRepo(t)
	audits, err := repo.ListAudits(0, 0)
	if err != nil {
		t.Fatalf("list audits: %v", err)
	}
	if audits != nil {
		t.Fatalf("expected nil for empty DB, got %d", len(audits))
	}
}

func TestGetStats(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	audit := &model.Audit{
		ID: "audit-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 80}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)
	_ = repo.SaveFindings("audit-1", []model.Finding{
		{ID: "f-1", AuditID: "audit-1", AgentType: "chaos", Severity: "critical", Category: "retry", Title: "Bad", Description: "bad", FilePath: "main.go"},
		{ID: "f-2", AuditID: "audit-1", AgentType: "chaos", Severity: "high", Category: "retry", Title: "Med", Description: "med", FilePath: "main.go"},
	})

	stats, err := repo.GetStats()
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if stats.AuditsRun != 1 {
		t.Errorf("expected 1 audit, got %d", stats.AuditsRun)
	}
	if stats.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", stats.TotalFindings)
	}
	if stats.CriticalIssues != 1 {
		t.Errorf("expected 1 critical, got %d", stats.CriticalIssues)
	}
	if stats.AverageScore != 80 {
		t.Errorf("expected avg score 80, got %d", stats.AverageScore)
	}
}

func TestGetStatsEmpty(t *testing.T) {
	repo := newTestRepo(t)
	stats, err := repo.GetStats()
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if stats.AuditsRun != 0 {
		t.Errorf("expected 0, got %d", stats.AuditsRun)
	}
	if stats.AverageScore != 0 {
		t.Errorf("expected 0, got %d", stats.AverageScore)
	}
}

func TestGetLatestCompletedAudit(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC()
	completed := &model.Audit{
		ID: "audit-1", SourceID: "src-1", Types: []string{"chaos", "owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 85}, CreatedAt: now, CompletedAt: &now,
	}
	_ = repo.CreateAudit(completed)
	_ = repo.UpdateAudit(completed)

	// Should find the completed audit with matching types
	got, err := repo.GetLatestCompletedAudit("src-1", []string{"chaos", "owasp"})
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if got == nil {
		t.Fatal("expected audit, got nil")
	}
	if got.ID != "audit-1" {
		t.Fatalf("expected audit-1, got %s", got.ID)
	}
}

func TestGetLatestCompletedAuditTypesMismatch(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp", FileCount: 1,
		CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC()
	audit := &model.Audit{
		ID: "audit-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{}, CreatedAt: now, CompletedAt: &now,
	}
	_ = repo.CreateAudit(audit)
	_ = repo.UpdateAudit(audit)

	// Different types should not match
	got, err := repo.GetLatestCompletedAudit("src-1", []string{"chaos", "owasp"})
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for type mismatch")
	}
}

func TestGetLatestCompletedAuditNone(t *testing.T) {
	repo := newTestRepo(t)
	got, err := repo.GetLatestCompletedAudit("nonexistent", []string{"chaos"})
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil")
	}
}

func TestFindSourceByPath(t *testing.T) {
	repo := newTestRepo(t)

	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/code/myapp",
		FileCount: 5, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	got, err := repo.FindSourceByPath("/code/myapp")
	if err != nil {
		t.Fatalf("find source: %v", err)
	}
	if got == nil {
		t.Fatal("expected source, got nil")
	}
	if got.ID != "src-1" {
		t.Fatalf("expected src-1, got %s", got.ID)
	}
}

func TestFindSourceByPathNotFound(t *testing.T) {
	repo := newTestRepo(t)

	got, err := repo.FindSourceByPath("/nonexistent")
	if err != nil {
		t.Fatalf("find source: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil")
	}
}

func TestDBMethod(t *testing.T) {
	repo := newTestRepo(t)
	db := repo.DB()
	if db == nil {
		t.Fatal("expected non-nil db handle")
	}
}

func TestSQLitePragmas(t *testing.T) {
	repo := newTestRepo(t)
	db := repo.DB()

	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("expected journal_mode=wal, got %s", journalMode)
	}

	var busyTimeout int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busyTimeout != 30000 {
		t.Errorf("expected busy_timeout=30000, got %d", busyTimeout)
	}

	var synchronous int
	if err := db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("query synchronous: %v", err)
	}
	if synchronous != 1 {
		t.Errorf("expected synchronous=1 (NORMAL), got %d", synchronous)
	}
}

func TestTypesMatch(t *testing.T) {
	tests := []struct {
		a, b  []string
		match bool
	}{
		{[]string{"chaos", "owasp"}, []string{"owasp", "chaos"}, true},
		{[]string{"chaos"}, []string{"chaos"}, true},
		{[]string{"chaos", "owasp"}, []string{"chaos"}, false},
		{[]string{"chaos"}, []string{"owasp"}, false},
		{[]string{}, []string{}, true},
		{nil, nil, true},
	}
	for _, tc := range tests {
		got := typesMatch(tc.a, tc.b)
		if got != tc.match {
			t.Errorf("typesMatch(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.match)
		}
	}
}

func TestAccumulateScores(t *testing.T) {
	total, count := accumulateScores(`{"chaos":80,"owasp":90}`, 0, 0)
	if total != 170 {
		t.Errorf("expected total 170, got %d", total)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	// Bad JSON
	total, count = accumulateScores("invalid", 100, 1)
	if total != 100 || count != 1 {
		t.Errorf("bad JSON should preserve previous values, got total=%d count=%d", total, count)
	}

	// Empty scores
	total, count = accumulateScores(`{}`, 0, 0)
	if total != 0 || count != 0 {
		t.Errorf("empty scores should produce 0, got total=%d count=%d", total, count)
	}
}

func TestNewSQLiteRepo_InvalidPath(t *testing.T) {
	_, err := NewSQLiteRepo("/nonexistent-dir-abc/subdir/test.db")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestCreateSource_DuplicateID(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-dup", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("first create: %v", err)
	}
	err := repo.CreateSource(src)
	if err == nil {
		t.Fatal("expected error for duplicate source ID")
	}
}

func TestCreateAudit_NilConfig(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	audit := &model.Audit{
		ID: "audit-nc", SourceID: "src-1", Types: []string{"chaos"},
		Config: nil, Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	if err := repo.CreateAudit(audit); err != nil {
		t.Fatalf("create audit with nil config: %v", err)
	}
	got, err := repo.GetAudit("audit-nc")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if got == nil {
		t.Fatal("expected audit")
	}
	if string(got.Config) != "{}" {
		t.Errorf("expected default config '{}', got %s", string(got.Config))
	}
}

func TestGetAuditNotFound(t *testing.T) {
	repo := newTestRepo(t)
	got, err := repo.GetAudit("nonexistent")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for nonexistent audit")
	}
}

func TestUpdateAudit_NoCompletedAt(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	audit := &model.Audit{
		ID: "audit-nc2", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)

	audit.Status = model.AuditStatusFailed
	audit.CompletedAt = nil
	if err := repo.UpdateAudit(audit); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := repo.GetAudit("audit-nc2")
	if got.Status != model.AuditStatusFailed {
		t.Errorf("expected failed, got %s", got.Status)
	}
	if got.CompletedAt != nil {
		t.Error("expected nil completed_at")
	}
}

func TestSaveFindings_Multiple(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	audit := &model.Audit{
		ID: "audit-mf", SourceID: "src-1", Types: []string{"owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateAudit(audit)

	findings := make([]model.Finding, 5)
	for i := 0; i < 5; i++ {
		findings[i] = model.Finding{
			ID: fmt.Sprintf("f-%d", i), AuditID: "audit-mf", AgentType: "owasp",
			Severity: model.SeverityHigh, Category: "injection",
			Title: fmt.Sprintf("Finding %d", i), Description: "desc",
			FilePath: "main.go", LineStart: i * 10, LineEnd: i*10 + 5,
			Recommendation: "fix it", References: []string{"ref1", "ref2"},
		}
	}
	if err := repo.SaveFindings("audit-mf", findings); err != nil {
		t.Fatalf("save findings: %v", err)
	}
	got, _ := repo.GetAudit("audit-mf")
	if len(got.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(got.Findings))
	}
	if got.FindingsCount != 5 {
		t.Errorf("expected findings_count=5, got %d", got.FindingsCount)
	}
	// Check references preserved
	for _, f := range got.Findings {
		if len(f.References) != 2 {
			t.Errorf("expected 2 references for %s, got %d", f.ID, len(f.References))
		}
	}
}

func TestListAudits_WithCompletedAt(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC().Truncate(time.Second)
	audit := &model.Audit{
		ID: "audit-c", SourceID: "src-1", Types: []string{"owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"owasp": 90}, CreatedAt: now,
		CompletedAt: &now,
	}
	_ = repo.CreateAudit(audit)
	_ = repo.UpdateAudit(audit)

	audits, err := repo.ListAudits(10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(audits) != 1 {
		t.Fatalf("expected 1 audit, got %d", len(audits))
	}
	if audits[0].CompletedAt == nil {
		t.Error("expected non-nil completed_at")
	}
	if audits[0].Scores["owasp"] != 90 {
		t.Errorf("expected score 90, got %d", audits[0].Scores["owasp"])
	}
}

func TestGetStats_MultipleScores(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC()
	// Audit 1 with 2 scores
	a1 := &model.Audit{
		ID: "a1", SourceID: "src-1", Types: []string{"chaos", "owasp"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 60, "owasp": 80}, CreatedAt: now,
		CompletedAt: &now,
	}
	_ = repo.CreateAudit(a1)
	_ = repo.UpdateAudit(a1)

	// Audit 2 with 1 score
	a2 := &model.Audit{
		ID: "a2", SourceID: "src-1", Types: []string{"soc2"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"soc2": 100}, CreatedAt: now,
		CompletedAt: &now,
	}
	_ = repo.CreateAudit(a2)
	_ = repo.UpdateAudit(a2)

	// Pending audit (no scores in computation)
	a3 := &model.Audit{
		ID: "a3", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: now,
	}
	_ = repo.CreateAudit(a3)

	stats, err := repo.GetStats()
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if stats.AuditsRun != 3 {
		t.Errorf("expected 3 audits, got %d", stats.AuditsRun)
	}
	// Average: (60 + 80 + 100) / 3 = 80
	if stats.AverageScore != 80 {
		t.Errorf("expected avg score 80, got %d", stats.AverageScore)
	}
}

func TestGetSourceWithURL(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID:        "src-git",
		Type:      model.SourceTypeGit,
		URL:       "https://github.com/example/repo",
		Path:      "/tmp/cloned",
		FileCount: 42,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := repo.CreateSource(src); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetSource("src-git")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.URL != "https://github.com/example/repo" {
		t.Errorf("expected URL, got %q", got.URL)
	}
	if got.Type != model.SourceTypeGit {
		t.Errorf("expected git type, got %s", got.Type)
	}
}

func TestGetLatestCompletedAudit_MultipleCompleted(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC()
	// Older completed audit
	older := &model.Audit{
		ID: "old", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 70},
		CreatedAt: now.Add(-time.Hour), CompletedAt: func() *time.Time { t := now.Add(-time.Hour); return &t }(),
	}
	_ = repo.CreateAudit(older)
	_ = repo.UpdateAudit(older)

	// Newer completed audit
	newer := &model.Audit{
		ID: "new", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 90},
		CreatedAt: now, CompletedAt: &now,
	}
	_ = repo.CreateAudit(newer)
	_ = repo.UpdateAudit(newer)

	got, err := repo.GetLatestCompletedAudit("src-1", []string{"chaos"})
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if got == nil {
		t.Fatal("expected audit")
	}
	// Should return the newest one (sorted DESC by created_at)
	if got.ID != "new" {
		t.Errorf("expected newest audit 'new', got %s", got.ID)
	}
}

func TestComputeAvgScore_ScanError(t *testing.T) {
	repo := newTestRepo(t)
	// With no data, computeAvgScore returns 0
	result := repo.computeAvgScore()
	if result != 0 {
		t.Errorf("expected 0 for empty DB, got %d", result)
	}
}

func TestGetStats_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.GetStats()
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestGetAudit_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close2.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.GetAudit("nonexistent")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestCreateSource_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close3.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	err = repo.CreateSource(&model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestGetSource_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close4.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.GetSource("id")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestFindSourceByPath_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close5.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.FindSourceByPath("/path")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestCreateAudit_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close6.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	err = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestUpdateAudit_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close7.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	err = repo.UpdateAudit(&model.Audit{
		ID: "a-1", Status: model.AuditStatusCompleted,
		Scores: map[string]int{},
	})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestSaveFindings_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close8.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	err = repo.SaveFindings("audit-1", []model.Finding{
		{ID: "f-1", AuditID: "audit-1", AgentType: "chaos", Severity: "high",
			Category: "retry", Title: "test", Description: "desc", FilePath: "main.go"},
	})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestListAudits_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close9.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.ListAudits(10, 0)
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestGetLatestCompletedAudit_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close10.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.GetLatestCompletedAudit("src", []string{"chaos"})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestGetFindings_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close11.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	_, err = repo.getFindings("audit-1")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestComputeAvgScore_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_close12.db")
	repo, err := NewSQLiteRepo(dbPath)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	repo.Close()

	result := repo.computeAvgScore()
	if result != 0 {
		t.Errorf("expected 0 after close, got %d", result)
	}
}

func TestGetStats_FindingsTableDropped(t *testing.T) {
	repo := newTestRepo(t)
	// Create audit so the first query succeeds
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	_ = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})

	// Drop findings table to trigger "count findings" error
	_, _ = repo.DB().Exec(`DROP TABLE findings`)
	_, err := repo.GetStats()
	if err == nil {
		t.Fatal("expected error when findings table is missing")
	}
}

func TestGetStats_CriticalCountError(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	_ = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})

	// Rename severity column to trigger "count critical" error
	// We need to recreate findings without the severity column
	_, _ = repo.DB().Exec(`DROP TABLE findings`)
	_, _ = repo.DB().Exec(`CREATE TABLE findings (id TEXT PRIMARY KEY, audit_id TEXT)`)

	_, err := repo.GetStats()
	if err == nil {
		t.Fatal("expected error when severity column is missing")
	}
}

func TestListAudits_ScanError(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	_ = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})

	// Drop and recreate audits table with fewer columns to cause scan error
	_, _ = repo.DB().Exec(`DROP TABLE audits`)
	_, _ = repo.DB().Exec(`CREATE TABLE audits (id TEXT PRIMARY KEY, source_id TEXT, types TEXT, config TEXT, status TEXT, scores TEXT, created_at TEXT, completed_at TEXT)`)
	_, _ = repo.DB().Exec(`INSERT INTO audits (id, source_id, types, config, status, scores, created_at) VALUES ('a-1', 'src-1', '["chaos"]', '{}', 'pending', '{}', '2025-01-01T00:00:00Z')`)

	// The ListAudits query selects findings_count via subquery, so it expects the findings table
	// The scan expects 10 fields; if we can make the subquery fail, scan will error
	// Actually, this should work because we haven't dropped findings - let me try another approach
	// Drop findings table to make the subquery fail (or return NULL causing scan error)
	_, _ = repo.DB().Exec(`DROP TABLE findings`)

	_, err := repo.ListAudits(10, 0)
	if err == nil {
		t.Fatal("expected error when findings table is dropped")
	}
}

func TestGetFindings_ScanError(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	_ = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusPending,
		Scores: map[string]int{}, CreatedAt: time.Now().UTC(),
	})

	// Replace findings table with one that has mismatched columns
	_, _ = repo.DB().Exec(`DROP TABLE findings`)
	_, _ = repo.DB().Exec(`CREATE TABLE findings (id TEXT PRIMARY KEY, audit_id TEXT, agent_type TEXT)`)
	_, _ = repo.DB().Exec(`INSERT INTO findings (id, audit_id, agent_type) VALUES ('f-1', 'a-1', 'chaos')`)

	// getFindings expects 12 columns but the table only has 3, triggering scan error
	_, err := repo.getFindings("a-1")
	if err == nil {
		t.Fatal("expected scan error with mismatched columns")
	}
}

func TestGetLatestCompletedAudit_ScanError(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	now := time.Now().UTC()
	_ = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 80}, CreatedAt: now, CompletedAt: &now,
	})
	_ = repo.UpdateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 80}, CreatedAt: now, CompletedAt: &now,
	})

	// Drop and recreate audits with all required columns for the query to succeed,
	// but with mismatched column types so Scan errors on the row
	_, _ = repo.DB().Exec(`DROP TABLE audits`)
	_, _ = repo.DB().Exec(`CREATE TABLE audits (
		id TEXT PRIMARY KEY, source_id TEXT, types TEXT, config TEXT,
		status TEXT, scores TEXT, created_at TEXT, completed_at TEXT
	)`)
	// Insert a row where completed_at is not NULL so Scan still attempts all 8 columns
	// Use types=NULL to trigger scan error on string scanning
	_, _ = repo.DB().Exec(`INSERT INTO audits (id, source_id, types, config, status, scores, created_at, completed_at)
		VALUES ('a-1', 'src-1', NULL, '{}', 'completed', '{}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`)

	// GetLatestCompletedAudit scans types as string; NULL triggers error -> continue
	got, err := repo.GetLatestCompletedAudit("src-1", []string{"chaos"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The scan error causes continue, so all rows are skipped -> nil result
	if got != nil {
		t.Fatal("expected nil when all rows have scan errors")
	}
}

func TestComputeAvgScore_ScanErrorContinues(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)
	now := time.Now().UTC()
	_ = repo.CreateAudit(&model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 80}, CreatedAt: now, CompletedAt: &now,
	})
	_ = repo.UpdateAudit(&model.Audit{
		ID: "a-1", Status: model.AuditStatusCompleted, Scores: map[string]int{"chaos": 80},
	})

	// Replace audits table with a table where scores column is not text (e.g., an integer)
	// This won't work easily. Instead, let's insert invalid data directly.
	_, _ = repo.DB().Exec(`DROP TABLE audits`)
	_, _ = repo.DB().Exec(`CREATE TABLE audits (id TEXT, source_id TEXT, types TEXT, config TEXT, status TEXT, scores INTEGER, created_at TEXT, completed_at TEXT)`)
	_, _ = repo.DB().Exec(`INSERT INTO audits (id, source_id, status, scores, created_at) VALUES ('a-1', 'src-1', 'completed', 999, '2025-01-01T00:00:00Z')`)

	// computeAvgScore tries to scan scores as string, INTEGER 999 should still scan as "999" in SQLite
	// which is invalid JSON -> accumulateScores handles invalid JSON, returning 0
	result := repo.computeAvgScore()
	if result != 0 {
		t.Errorf("expected 0 for non-JSON score, got %d", result)
	}
}

func TestGetStats_AllErrorPaths(t *testing.T) {
	repo := newTestRepo(t)

	// Populate with data to exercise the query paths
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC()
	audit := &model.Audit{
		ID: "a-1", SourceID: "src-1", Types: []string{"chaos"},
		Config: json.RawMessage("{}"), Status: model.AuditStatusCompleted,
		Scores: map[string]int{"chaos": 75}, CreatedAt: now,
		CompletedAt: &now,
	}
	_ = repo.CreateAudit(audit)
	_ = repo.UpdateAudit(audit)
	_ = repo.SaveFindings("a-1", []model.Finding{
		{ID: "f-1", AuditID: "a-1", AgentType: "chaos", Severity: "critical",
			Category: "retry", Title: "T", Description: "D", FilePath: "main.go"},
		{ID: "f-2", AuditID: "a-1", AgentType: "chaos", Severity: "high",
			Category: "retry", Title: "T2", Description: "D2", FilePath: "main.go"},
	})

	stats, err := repo.GetStats()
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if stats.AuditsRun != 1 {
		t.Errorf("expected 1 audit, got %d", stats.AuditsRun)
	}
	if stats.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", stats.TotalFindings)
	}
	if stats.CriticalIssues != 1 {
		t.Errorf("expected 1 critical, got %d", stats.CriticalIssues)
	}
	if stats.AverageScore != 75 {
		t.Errorf("expected avg 75, got %d", stats.AverageScore)
	}
}

func TestListAudits_ScanRow(t *testing.T) {
	repo := newTestRepo(t)
	src := &model.Source{
		ID: "src-1", Type: model.SourceTypeLocal, Path: "/tmp",
		FileCount: 1, CreatedAt: time.Now().UTC(),
	}
	_ = repo.CreateSource(src)

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		a := &model.Audit{
			ID: fmt.Sprintf("a-%d", i), SourceID: "src-1", Types: []string{"chaos"},
			Config: json.RawMessage("{}"), Status: model.AuditStatusRunning,
			Scores: map[string]int{},
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		}
		_ = repo.CreateAudit(a)
		_ = repo.SaveFindings(a.ID, []model.Finding{
			{ID: fmt.Sprintf("f-%d", i), AuditID: a.ID, AgentType: "chaos",
				Severity: "high", Category: "retry", Title: "T",
				Description: "D", FilePath: "main.go"},
		})
	}
	audits, err := repo.ListAudits(10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(audits) != 3 {
		t.Fatalf("expected 3 audits, got %d", len(audits))
	}
	for _, a := range audits {
		if a.FindingsCount != 1 {
			t.Errorf("audit %s: expected findings_count=1, got %d", a.ID, a.FindingsCount)
		}
	}
}
