package repository

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"

	_ "modernc.org/sqlite"
)

func newTestMemoryRepo(t *testing.T) *SQLiteMemoryRepo {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_memory.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new memory repo: %v", err)
	}
	return repo
}

func sampleMemory(id, auditID string) *model.AuditMemory {
	return &model.AuditMemory{
		ID:                id,
		AuditID:           auditID,
		AgentType:         "owasp",
		CodebasePath:      "/tmp/project",
		FindingType:       "vulnerability",
		Title:             "SQL Injection in login",
		Content:           "The login handler concatenates user input directly into SQL query",
		Severity:          model.SeverityHigh,
		ComplianceRef:     "A03:2021",
		Category:          "injection",
		Keywords:          []string{"sql", "injection", "login"},
		Tags:              []string{"security", "critical-path"},
		FilePaths:         []string{"auth/login.go", "auth/db.go"},
		RemediationStatus: "open",
	}
}

func TestStoreAndGetMemory(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")

	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store memory: %v", err)
	}

	got, err := repo.GetMemory("mem-1")
	if err != nil {
		t.Fatalf("get memory: %v", err)
	}
	if got == nil {
		t.Fatal("expected memory, got nil")
	}
	if got.Title != "SQL Injection in login" {
		t.Fatalf("expected title 'SQL Injection in login', got %s", got.Title)
	}
	if got.Severity != model.SeverityHigh {
		t.Fatalf("expected severity high, got %s", got.Severity)
	}
	if len(got.Keywords) != 3 {
		t.Fatalf("expected 3 keywords, got %d", len(got.Keywords))
	}
	if got.Keywords[0] != "sql" {
		t.Fatalf("expected keyword 'sql', got %s", got.Keywords[0])
	}
	if len(got.FilePaths) != 2 {
		t.Fatalf("expected 2 file_paths, got %d", len(got.FilePaths))
	}
	if got.ComplianceRef != "A03:2021" {
		t.Fatalf("expected compliance_ref 'A03:2021', got %s", got.ComplianceRef)
	}
}

func TestStoreMemoryIdempotent(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")

	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("first store: %v", err)
	}
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("second store should not error: %v", err)
	}

	got, err := repo.GetMemory("mem-1")
	if err != nil {
		t.Fatalf("get memory: %v", err)
	}
	if got == nil {
		t.Fatal("expected memory, got nil")
	}
}

func TestGetMemoryNotFound(t *testing.T) {
	repo := newTestMemoryRepo(t)
	got, err := repo.GetMemory("nonexistent")
	if err != nil {
		t.Fatalf("get memory: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil, got memory")
	}
}

func TestStoreAndRetrieveEmbedding(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store memory: %v", err)
	}

	embedding := []float32{0.1, 0.2, 0.3, 0.4, 0.5}
	if err := repo.StoreEmbedding("mem-1", embedding); err != nil {
		t.Fatalf("store embedding: %v", err)
	}

	// Overwrite should work
	embedding2 := []float32{0.5, 0.4, 0.3, 0.2, 0.1}
	if err := repo.StoreEmbedding("mem-1", embedding2); err != nil {
		t.Fatalf("update embedding: %v", err)
	}
}

func TestSearchMemories(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem1 := sampleMemory("mem-1", "audit-1")
	mem2 := sampleMemory("mem-2", "audit-1")
	mem2.Title = "XSS in profile page"
	mem2.Content = "User-controlled data rendered without escaping"
	mem2.Keywords = []string{"xss", "profile"}

	if err := repo.StoreMemory(mem1); err != nil {
		t.Fatalf("store mem1: %v", err)
	}
	if err := repo.StoreMemory(mem2); err != nil {
		t.Fatalf("store mem2: %v", err)
	}

	// Search by title
	results, err := repo.SearchMemories("SQL Injection", nil, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "mem-1" {
		t.Fatalf("expected mem-1, got %s", results[0].ID)
	}

	// Search by content
	results, err = repo.SearchMemories("escaping", nil, 10)
	if err != nil {
		t.Fatalf("search by content: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "mem-2" {
		t.Fatalf("expected mem-2, got %s", results[0].ID)
	}

	// Search by keyword in JSON
	results, err = repo.SearchMemories("xss", nil, 10)
	if err != nil {
		t.Fatalf("search by keyword: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Default limit
	results, err = repo.SearchMemories("mem", nil, 0)
	if err != nil {
		t.Fatalf("search default limit: %v", err)
	}
	if len(results) > 20 {
		t.Fatalf("default limit exceeded: got %d", len(results))
	}
}

func TestSearchMemoriesIgnoresEmbedding(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Embedding is ignored; text search still works
	results, err := repo.SearchMemories("injection", []float32{0.1, 0.2}, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestFindSimilarByVector(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem1 := sampleMemory("mem-1", "audit-1")
	mem1.Keywords = []string{"sql", "injection", "auth"}

	mem2 := sampleMemory("mem-2", "audit-1")
	mem2.Title = "Another SQL issue"
	mem2.Keywords = []string{"sql", "query", "auth"}

	mem3 := sampleMemory("mem-3", "audit-1")
	mem3.Title = "Unrelated XSS"
	mem3.Keywords = []string{"xss", "profile"}

	for _, m := range []*model.AuditMemory{mem1, mem2, mem3} {
		if err := repo.StoreMemory(m); err != nil {
			t.Fatalf("store %s: %v", m.ID, err)
		}
	}

	// Find similar to mem-1 (by keyword overlap) excluding mem-1
	results, err := repo.FindSimilarByVector("mem-1", nil, 10)
	if err != nil {
		t.Fatalf("find similar: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 similar result (mem-2 shares keywords), got %d", len(results))
	}
	if results[0].ID != "mem-2" {
		t.Fatalf("expected mem-2, got %s", results[0].ID)
	}
}

func TestFindSimilarByVectorNoKeywords(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	mem.Keywords = []string{}
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store: %v", err)
	}

	results, err := repo.FindSimilarByVector("mem-1", nil, 10)
	if err != nil {
		t.Fatalf("find similar: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil for empty keywords, got %d results", len(results))
	}
}

func TestUpdateRemediation(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store: %v", err)
	}

	if err := repo.UpdateRemediation("mem-1", "resolved", "Fixed in PR #42"); err != nil {
		t.Fatalf("update remediation: %v", err)
	}

	got, err := repo.GetMemory("mem-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RemediationStatus != "resolved" {
		t.Fatalf("expected status 'resolved', got %s", got.RemediationStatus)
	}
	if got.RemediationNotes != "Fixed in PR #42" {
		t.Fatalf("expected notes 'Fixed in PR #42', got %s", got.RemediationNotes)
	}
}

func TestListMemoriesByAudit(t *testing.T) {
	repo := newTestMemoryRepo(t)

	mem1 := sampleMemory("mem-1", "audit-1")
	mem2 := sampleMemory("mem-2", "audit-1")
	mem3 := sampleMemory("mem-3", "audit-2")

	for _, m := range []*model.AuditMemory{mem1, mem2, mem3} {
		if err := repo.StoreMemory(m); err != nil {
			t.Fatalf("store %s: %v", m.ID, err)
		}
	}

	results, err := repo.ListMemoriesByAudit("audit-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	results, err = repo.ListMemoriesByAudit("audit-2")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestListByCodebasePath(t *testing.T) {
	repo := newTestMemoryRepo(t)

	mem1 := sampleMemory("mem-1", "audit-1")
	mem1.AgentType = "owasp"

	mem2 := sampleMemory("mem-2", "audit-1")
	mem2.AgentType = "chaos"

	mem3 := sampleMemory("mem-3", "audit-1")
	mem3.CodebasePath = "/tmp/other"

	for _, m := range []*model.AuditMemory{mem1, mem2, mem3} {
		if err := repo.StoreMemory(m); err != nil {
			t.Fatalf("store %s: %v", m.ID, err)
		}
	}

	// All agent types for path
	results, err := repo.ListByCodebasePath("/tmp/project", "", 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Filter by agent type
	results, err = repo.ListByCodebasePath("/tmp/project", "owasp", 10)
	if err != nil {
		t.Fatalf("list with agent type: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].AgentType != "owasp" {
		t.Fatalf("expected owasp, got %s", results[0].AgentType)
	}

	// Default limit
	results, err = repo.ListByCodebasePath("/tmp/project", "", 0)
	if err != nil {
		t.Fatalf("default limit: %v", err)
	}
	if len(results) > 50 {
		t.Fatalf("default limit exceeded")
	}
}

func TestListRecent(t *testing.T) {
	repo := newTestMemoryRepo(t)

	for i := 0; i < 5; i++ {
		mem := sampleMemory("mem-"+string(rune('a'+i)), "audit-1")
		mem.Title = "Finding " + string(rune('A'+i))
		if err := repo.StoreMemory(mem); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	results, err := repo.ListRecent(3)
	if err != nil {
		t.Fatalf("list recent: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Default limit
	results, err = repo.ListRecent(0)
	if err != nil {
		t.Fatalf("list recent default: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
}

func TestStoreAndGetEdges(t *testing.T) {
	repo := newTestMemoryRepo(t)

	mem1 := sampleMemory("mem-1", "audit-1")
	mem2 := sampleMemory("mem-2", "audit-1")
	mem2.Title = "Related finding"
	mem2.Severity = model.SeverityCritical

	if err := repo.StoreMemory(mem1); err != nil {
		t.Fatalf("store mem1: %v", err)
	}
	if err := repo.StoreMemory(mem2); err != nil {
		t.Fatalf("store mem2: %v", err)
	}

	edge := &model.MemoryEdge{
		SourceID:      "mem-1",
		TargetID:      "mem-2",
		RelationType:  "related",
		Strength:      0.9,
		Bidirectional: false,
		CreatedBy:     "owasp-agent",
	}
	if err := repo.StoreEdge(edge); err != nil {
		t.Fatalf("store edge: %v", err)
	}

	// Get edges from source
	edges, err := repo.GetEdges("mem-1")
	if err != nil {
		t.Fatalf("get edges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].RelationType != "related" {
		t.Fatalf("expected relation_type 'related', got %s", edges[0].RelationType)
	}
	if edges[0].TargetTitle != "Related finding" {
		t.Fatalf("expected target_title 'Related finding', got %s", edges[0].TargetTitle)
	}
	if edges[0].TargetSeverity != "critical" {
		t.Fatalf("expected target_severity 'critical', got %s", edges[0].TargetSeverity)
	}
	if edges[0].Strength != 0.9 {
		t.Fatalf("expected strength 0.9, got %f", edges[0].Strength)
	}
	if edges[0].CreatedBy != "owasp-agent" {
		t.Fatalf("expected created_by 'owasp-agent', got %s", edges[0].CreatedBy)
	}

	// Get edges from target (not bidirectional, should return empty)
	edges, err = repo.GetEdges("mem-2")
	if err != nil {
		t.Fatalf("get edges from target: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("expected 0 edges from target of unidirectional edge, got %d", len(edges))
	}
}

func TestStoreEdgeBidirectional(t *testing.T) {
	repo := newTestMemoryRepo(t)

	mem1 := sampleMemory("mem-1", "audit-1")
	mem2 := sampleMemory("mem-2", "audit-1")

	if err := repo.StoreMemory(mem1); err != nil {
		t.Fatalf("store mem1: %v", err)
	}
	if err := repo.StoreMemory(mem2); err != nil {
		t.Fatalf("store mem2: %v", err)
	}

	edge := &model.MemoryEdge{
		SourceID:      "mem-1",
		TargetID:      "mem-2",
		RelationType:  "similar",
		Strength:      0.8,
		Bidirectional: true,
		CreatedBy:     "system",
	}
	if err := repo.StoreEdge(edge); err != nil {
		t.Fatalf("store edge: %v", err)
	}

	// Both sides should see the edge
	edges1, err := repo.GetEdges("mem-1")
	if err != nil {
		t.Fatalf("get edges mem-1: %v", err)
	}
	if len(edges1) != 1 {
		t.Fatalf("expected 1 edge from mem-1, got %d", len(edges1))
	}

	edges2, err := repo.GetEdges("mem-2")
	if err != nil {
		t.Fatalf("get edges mem-2: %v", err)
	}
	if len(edges2) != 1 {
		t.Fatalf("expected 1 edge from mem-2, got %d", len(edges2))
	}
}

func TestStoreEdgeUpsert(t *testing.T) {
	repo := newTestMemoryRepo(t)

	mem1 := sampleMemory("mem-1", "audit-1")
	mem2 := sampleMemory("mem-2", "audit-1")
	if err := repo.StoreMemory(mem1); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := repo.StoreMemory(mem2); err != nil {
		t.Fatalf("store: %v", err)
	}

	edge := &model.MemoryEdge{
		SourceID: "mem-1", TargetID: "mem-2", RelationType: "related",
		Strength: 0.5, CreatedBy: "agent",
	}
	if err := repo.StoreEdge(edge); err != nil {
		t.Fatalf("first store edge: %v", err)
	}

	// Update strength via upsert
	edge.Strength = 0.95
	if err := repo.StoreEdge(edge); err != nil {
		t.Fatalf("upsert edge: %v", err)
	}

	edges, err := repo.GetEdges("mem-1")
	if err != nil {
		t.Fatalf("get edges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge after upsert, got %d", len(edges))
	}
	if edges[0].Strength != 0.95 {
		t.Fatalf("expected strength 0.95, got %f", edges[0].Strength)
	}
}

func TestGetEdgesEmpty(t *testing.T) {
	repo := newTestMemoryRepo(t)
	edges, err := repo.GetEdges("nonexistent")
	if err != nil {
		t.Fatalf("get edges: %v", err)
	}
	if edges != nil {
		t.Fatalf("expected nil, got %d edges", len(edges))
	}
}

func TestSearchMemoriesNoResults(t *testing.T) {
	repo := newTestMemoryRepo(t)
	results, err := repo.SearchMemories("nonexistent-query-xyz", nil, 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil, got %d results", len(results))
	}
}

func TestListMemoriesByAuditEmpty(t *testing.T) {
	repo := newTestMemoryRepo(t)
	results, err := repo.ListMemoriesByAudit("nonexistent")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil, got %d results", len(results))
	}
}

func TestListRecentEmpty(t *testing.T) {
	repo := newTestMemoryRepo(t)
	results, err := repo.ListRecent(10)
	if err != nil {
		t.Fatalf("list recent: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil, got %d results", len(results))
	}
}

func TestMemoryCreatedAtParsed(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := repo.GetMemory("mem-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("expected non-zero created_at")
	}
	// CreatedAt should be within the last minute
	if time.Since(got.CreatedAt) > time.Minute {
		t.Fatalf("created_at too old: %v", got.CreatedAt)
	}
}

func TestNewSQLiteMemoryRepo_MigrationSuccess(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mem_mig.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
}

func TestStoreMemory_NilSliceFields(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := &model.AuditMemory{
		ID:                "mem-nil",
		AuditID:           "a-1",
		AgentType:         "owasp",
		CodebasePath:      "/tmp",
		FindingType:       "vuln",
		Title:             "Test nil slices",
		Content:           "Content",
		Severity:          model.SeverityLow,
		Keywords:          nil,
		Tags:              nil,
		FilePaths:         nil,
		RemediationStatus: "open",
	}
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := repo.GetMemory("mem-nil")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected memory")
	}
	if got.Title != "Test nil slices" {
		t.Errorf("expected title, got %s", got.Title)
	}
}

func TestStoreEmbedding_NewRecord(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-emb", "audit-1")
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store memory: %v", err)
	}
	emb := []float32{0.1, 0.2, 0.3}
	if err := repo.StoreEmbedding("mem-emb", emb); err != nil {
		t.Fatalf("store embedding: %v", err)
	}
}

func TestSearchMemories_DefaultLimit(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	if err := repo.StoreMemory(mem); err != nil {
		t.Fatalf("store: %v", err)
	}
	results, err := repo.SearchMemories("SQL", nil, -1)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
}

func TestFindSimilarByVector_DefaultLimit(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem1 := sampleMemory("mem-1", "audit-1")
	mem1.Keywords = []string{"sql", "injection"}
	mem2 := sampleMemory("mem-2", "audit-1")
	mem2.Title = "Another SQL"
	mem2.Keywords = []string{"sql", "query"}
	for _, m := range []*model.AuditMemory{mem1, mem2} {
		if err := repo.StoreMemory(m); err != nil {
			t.Fatalf("store: %v", err)
		}
	}
	results, err := repo.FindSimilarByVector("mem-1", nil, -1)
	if err != nil {
		t.Fatalf("find similar: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
}

func TestFindSimilarByVector_NotFound(t *testing.T) {
	repo := newTestMemoryRepo(t)
	_, err := repo.FindSimilarByVector("nonexistent", nil, 10)
	if err == nil {
		t.Fatal("expected error for nonexistent memory")
	}
}

func TestListByCodebasePath_EmptyResults(t *testing.T) {
	repo := newTestMemoryRepo(t)
	results, err := repo.ListByCodebasePath("/no/such/path", "", 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil, got %d", len(results))
	}
}

func TestUpdateRemediation_Nonexistent(t *testing.T) {
	repo := newTestMemoryRepo(t)
	// Updating a nonexistent record doesn't error in SQLite (0 rows affected)
	err := repo.UpdateRemediation("nonexistent", "resolved", "notes")
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestStoreEdge_Bidirectional(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem1 := sampleMemory("mem-e1", "audit-1")
	mem2 := sampleMemory("mem-e2", "audit-1")
	_ = repo.StoreMemory(mem1)
	_ = repo.StoreMemory(mem2)

	edge := &model.MemoryEdge{
		SourceID:      "mem-e1",
		TargetID:      "mem-e2",
		RelationType:  "similar",
		Strength:      0.85,
		Bidirectional: true,
		CreatedBy:     "test",
	}
	if err := repo.StoreEdge(edge); err != nil {
		t.Fatalf("store edge: %v", err)
	}

	// Both sides should see it
	edges1, err := repo.GetEdges("mem-e1")
	if err != nil {
		t.Fatalf("get edges: %v", err)
	}
	if len(edges1) != 1 {
		t.Fatalf("expected 1 edge from source, got %d", len(edges1))
	}
	if !edges1[0].Bidirectional {
		t.Error("expected bidirectional=true")
	}

	edges2, err := repo.GetEdges("mem-e2")
	if err != nil {
		t.Fatalf("get edges: %v", err)
	}
	if len(edges2) != 1 {
		t.Fatalf("expected 1 edge from target, got %d", len(edges2))
	}
}

func TestListRecent_DefaultLimit(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	_ = repo.StoreMemory(mem)
	results, err := repo.ListRecent(-1)
	if err != nil {
		t.Fatalf("list recent: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
}

func TestListByCodebasePath_DefaultLimit(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	_ = repo.StoreMemory(mem)
	results, err := repo.ListByCodebasePath("/tmp/project", "", -1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1, got %d", len(results))
	}
}

func TestStoreMemory_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_mem.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	err = repo.StoreMemory(sampleMemory("m-1", "a-1"))
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestStoreEmbedding_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_emb.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	err = repo.StoreEmbedding("m-1", []float32{0.1})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestSearchMemories_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_search.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	_, err = repo.SearchMemories("query", nil, 10)
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestGetMemory_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_getmem.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	_, err = repo.GetMemory("m-1")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestUpdateRemediation_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_upd.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	err = repo.UpdateRemediation("m-1", "resolved", "notes")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestListMemoriesByAudit_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_list.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	_, err = repo.ListMemoriesByAudit("a-1")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestListByCodebasePath_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_listpath.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	_, err = repo.ListByCodebasePath("/path", "", 10)
	if err == nil {
		t.Fatal("expected error after DB close for empty agent type")
	}

	// Reopen for agent type path
	db2, _ := sql.Open("sqlite", filepath.Join(t.TempDir(), "close_listpath2.db"))
	repo2, _ := NewSQLiteMemoryRepo(db2)
	db2.Close()

	_, err = repo2.ListByCodebasePath("/path", "owasp", 10)
	if err == nil {
		t.Fatal("expected error after DB close for specific agent type")
	}
}

func TestListRecent_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_recent.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	_, err = repo.ListRecent(10)
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestStoreEdge_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_edge.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	err = repo.StoreEdge(&model.MemoryEdge{
		SourceID: "m-1", TargetID: "m-2", RelationType: "related",
		Strength: 0.5, CreatedBy: "test",
	})
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestGetEdges_AfterDBClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "close_getedges.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	repo, err := NewSQLiteMemoryRepo(db)
	if err != nil {
		t.Fatalf("new repo: %v", err)
	}
	db.Close()

	_, err = repo.GetEdges("m-1")
	if err == nil {
		t.Fatal("expected error after DB close")
	}
}

func TestNewSQLiteMemoryRepo_MigrationError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mig_err.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close() // Close before migration
	_, err = NewSQLiteMemoryRepo(db)
	if err == nil {
		t.Fatal("expected error for migration on closed DB")
	}
}

func TestFindSimilarByVector_QueryError(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	mem.Keywords = []string{"sql", "injection"}
	_ = repo.StoreMemory(mem)

	// Drop the audit_memories table and replace with one that has the keywords column
	// but is missing other columns so the query succeeds but scanMemories fails
	// Actually, let's just drop and recreate with minimal columns
	_, _ = repo.db.Exec(`DROP TABLE memory_embeddings`)
	_, _ = repo.db.Exec(`DROP TABLE memory_edges`)
	_, _ = repo.db.Exec(`DROP TABLE audit_memories`)
	_, _ = repo.db.Exec(`CREATE TABLE audit_memories (id TEXT PRIMARY KEY, keywords TEXT)`)
	_, _ = repo.db.Exec(`INSERT INTO audit_memories (id, keywords) VALUES ('mem-1', '["sql","injection"]')`)
	_, _ = repo.db.Exec(`INSERT INTO audit_memories (id, keywords) VALUES ('mem-2', '["sql","query"]')`)

	// FindSimilarByVector builds a query selecting 17 columns, but our table only has 2
	_, err := repo.FindSimilarByVector("mem-1", nil, 10)
	if err == nil {
		t.Fatal("expected error from scan with mismatched columns")
	}
}

func TestGetEdges_ScanError(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem1 := sampleMemory("mem-1", "audit-1")
	mem2 := sampleMemory("mem-2", "audit-1")
	_ = repo.StoreMemory(mem1)
	_ = repo.StoreMemory(mem2)
	_ = repo.StoreEdge(&model.MemoryEdge{
		SourceID: "mem-1", TargetID: "mem-2", RelationType: "related",
		Strength: 0.5, CreatedBy: "test",
	})

	// Replace memory_edges with a table that has fewer columns
	_, _ = repo.db.Exec(`DROP TABLE memory_edges`)
	_, _ = repo.db.Exec(`CREATE TABLE memory_edges (id INTEGER PRIMARY KEY, source_id TEXT, target_id TEXT, bidirectional INTEGER DEFAULT 0)`)
	_, _ = repo.db.Exec(`INSERT INTO memory_edges (source_id, target_id, bidirectional) VALUES ('mem-1', 'mem-2', 0)`)

	// GetEdges selects 10 columns but our table only has 4
	_, err := repo.GetEdges("mem-1")
	if err == nil {
		t.Fatal("expected scan error with mismatched edge columns")
	}
}

func TestScanMemories_ScanError(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-1", "audit-1")
	_ = repo.StoreMemory(mem)

	// Replace audit_memories table with minimal columns
	_, _ = repo.db.Exec(`DROP TABLE memory_embeddings`)
	_, _ = repo.db.Exec(`DROP TABLE memory_edges`)
	_, _ = repo.db.Exec(`DROP TABLE audit_memories`)
	_, _ = repo.db.Exec(`CREATE TABLE audit_memories (id TEXT PRIMARY KEY, audit_id TEXT)`)
	_, _ = repo.db.Exec(`INSERT INTO audit_memories (id, audit_id) VALUES ('mem-1', 'audit-1')`)

	// SearchMemories will query 17 columns but only 2 exist -> scan error
	_, err := repo.SearchMemories("mem", nil, 10)
	if err == nil {
		t.Fatal("expected scan error with mismatched memory columns")
	}
}

func TestMemory_FieldParsing(t *testing.T) {
	repo := newTestMemoryRepo(t)
	mem := sampleMemory("mem-fp", "audit-1")
	mem.ComplianceRef = "CC6.1"
	mem.Category = "injection"
	mem.RemediationNotes = "Fix by next sprint"
	_ = repo.StoreMemory(mem)

	got, err := repo.GetMemory("mem-fp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ComplianceRef != "CC6.1" {
		t.Errorf("compliance_ref: expected CC6.1, got %s", got.ComplianceRef)
	}
	if got.Category != "injection" {
		t.Errorf("category: expected injection, got %s", got.Category)
	}
	if got.AgentType != "owasp" {
		t.Errorf("agent_type: expected owasp, got %s", got.AgentType)
	}
	if len(got.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(got.Tags))
	}
}
