package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/embedding"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

func newMemoryServiceWithMock(repo *repository.MockMemoryRepository) *memoryService {
	// Use a real Client with no API key so Available() returns false
	// without nil pointer dereference.
	return &memoryService{
		repo:     repo,
		embedder: &embedding.Client{},
	}
}

func TestMemoryService_Store_SetsDefaults(t *testing.T) {
	var stored *model.AuditMemory
	repo := &repository.MockMemoryRepository{
		StoreMemoryFn: func(mem *model.AuditMemory) error {
			stored = mem
			return nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	mem := &model.AuditMemory{
		AuditID:     "a-1",
		Title:       "XSS found",
		FindingType: "injection",
	}
	err := svc.Store(mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stored.ID == "" {
		t.Error("expected ID to be generated")
	}
	if stored.RemediationStatus != "open" {
		t.Errorf("expected remediation_status=open, got %q", stored.RemediationStatus)
	}
}

func TestMemoryService_Store_PreservesExistingID(t *testing.T) {
	repo := &repository.MockMemoryRepository{
		StoreMemoryFn: func(mem *model.AuditMemory) error {
			return nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	mem := &model.AuditMemory{
		ID:                "custom-id",
		RemediationStatus: "resolved",
	}
	err := svc.Store(mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mem.ID != "custom-id" {
		t.Errorf("expected preserved id, got %q", mem.ID)
	}
	if mem.RemediationStatus != "resolved" {
		t.Errorf("expected preserved status, got %q", mem.RemediationStatus)
	}
}

func TestMemoryService_Store_RepoError(t *testing.T) {
	repoErr := errors.New("store failed")
	repo := &repository.MockMemoryRepository{
		StoreMemoryFn: func(mem *model.AuditMemory) error {
			return repoErr
		},
	}
	svc := newMemoryServiceWithMock(repo)

	err := svc.Store(&model.AuditMemory{ID: "m-1"})
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error, got %v", err)
	}
}

func TestMemoryService_Search_WithoutEmbedder(t *testing.T) {
	var gotQuery string
	var gotLimit int
	repo := &repository.MockMemoryRepository{
		SearchMemoriesFn: func(query string, emb []float32, limit int) ([]model.AuditMemory, error) {
			gotQuery = query
			gotLimit = limit
			if emb != nil {
				t.Error("expected nil embedding when embedder unavailable")
			}
			return []model.AuditMemory{{ID: "m-1"}}, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	results, err := svc.Search(&model.MemorySearchRequest{Query: "xss", Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotQuery != "xss" {
		t.Errorf("expected query=xss, got %q", gotQuery)
	}
	if gotLimit != 10 {
		t.Errorf("expected limit=10, got %d", gotLimit)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryService_Search_DefaultLimit(t *testing.T) {
	var gotLimit int
	repo := &repository.MockMemoryRepository{
		SearchMemoriesFn: func(query string, emb []float32, limit int) ([]model.AuditMemory, error) {
			gotLimit = limit
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.Search(&model.MemorySearchRequest{Query: "test", Limit: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != 20 {
		t.Errorf("expected default limit=20, got %d", gotLimit)
	}
}

func TestMemoryService_Get_Success(t *testing.T) {
	expected := &model.AuditMemory{ID: "m-1", Title: "Finding"}
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return expected, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	mem, err := svc.Get("m-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mem.ID != "m-1" {
		t.Errorf("got id=%q, want m-1", mem.ID)
	}
}

func TestMemoryService_Get_NotFound(t *testing.T) {
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryService_Get_RepoError(t *testing.T) {
	repoErr := errors.New("db error")
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return nil, repoErr
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.Get("m-1")
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error, got %v", err)
	}
}

func TestMemoryService_GetWithEdges_Success(t *testing.T) {
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return &model.AuditMemory{ID: "m-1"}, nil
		},
		GetEdgesFn: func(id string) ([]model.MemoryEdge, error) {
			return []model.MemoryEdge{{SourceID: "m-1", TargetID: "m-2"}}, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	result, err := svc.GetWithEdges("m-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "m-1" {
		t.Errorf("got id=%q, want m-1", result.ID)
	}
	if len(result.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(result.Edges))
	}
}

func TestMemoryService_GetWithEdges_NotFound(t *testing.T) {
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.GetWithEdges("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryService_GetWithEdges_EdgesError(t *testing.T) {
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return &model.AuditMemory{ID: "m-1"}, nil
		},
		GetEdgesFn: func(id string) ([]model.MemoryEdge, error) {
			return nil, errors.New("edge query failed")
		},
	}
	svc := newMemoryServiceWithMock(repo)

	result, err := svc.GetWithEdges("m-1")
	if err != nil {
		t.Fatalf("expected no error (edges error is non-fatal), got %v", err)
	}
	if result.Edges != nil {
		t.Errorf("expected nil edges on error, got %v", result.Edges)
	}
}

func TestMemoryService_UpdateRemediation(t *testing.T) {
	var gotID, gotStatus, gotNotes string
	repo := &repository.MockMemoryRepository{
		UpdateRemediationFn: func(id, status, notes string) error {
			gotID = id
			gotStatus = status
			gotNotes = notes
			return nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	err := svc.UpdateRemediation("m-1", "resolved", "Fixed in PR #42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != "m-1" || gotStatus != "resolved" || gotNotes != "Fixed in PR #42" {
		t.Errorf("unexpected args: id=%q status=%q notes=%q", gotID, gotStatus, gotNotes)
	}
}

func TestMemoryService_ListByAudit(t *testing.T) {
	var gotAuditID string
	repo := &repository.MockMemoryRepository{
		ListMemoriesByAuditFn: func(auditID string) ([]model.AuditMemory, error) {
			gotAuditID = auditID
			return []model.AuditMemory{{ID: "m-1"}}, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	results, err := svc.ListByAudit("a-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuditID != "a-1" {
		t.Errorf("expected audit_id=a-1, got %q", gotAuditID)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryService_ListByCodebasePath_DefaultLimit(t *testing.T) {
	var gotLimit int
	repo := &repository.MockMemoryRepository{
		ListByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			gotLimit = limit
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.ListByCodebasePath("/src", "owasp", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != 50 {
		t.Errorf("expected default limit=50, got %d", gotLimit)
	}
}

func TestMemoryService_ListByCodebasePath_CustomLimit(t *testing.T) {
	var gotLimit int
	repo := &repository.MockMemoryRepository{
		ListByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			gotLimit = limit
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.ListByCodebasePath("/src", "", 25)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != 25 {
		t.Errorf("expected limit=25, got %d", gotLimit)
	}
}

func TestMemoryService_ListRecent_DefaultLimit(t *testing.T) {
	var gotLimit int
	repo := &repository.MockMemoryRepository{
		ListRecentFn: func(limit int) ([]model.AuditMemory, error) {
			gotLimit = limit
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.ListRecent(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != 20 {
		t.Errorf("expected default limit=20, got %d", gotLimit)
	}
}

func TestMemoryService_ListRecent_CustomLimit(t *testing.T) {
	var gotLimit int
	repo := &repository.MockMemoryRepository{
		ListRecentFn: func(limit int) ([]model.AuditMemory, error) {
			gotLimit = limit
			return nil, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.ListRecent(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != 5 {
		t.Errorf("expected limit=5, got %d", gotLimit)
	}
}

func TestMemoryService_GetEdges(t *testing.T) {
	repo := &repository.MockMemoryRepository{
		GetEdgesFn: func(id string) ([]model.MemoryEdge, error) {
			return []model.MemoryEdge{{SourceID: id, TargetID: "m-2"}}, nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	edges, err := svc.GetEdges("m-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}
}

func TestMemoryService_StoreFindingsAsMemories(t *testing.T) {
	var storedCount int
	repo := &repository.MockMemoryRepository{
		StoreMemoryFn: func(mem *model.AuditMemory) error {
			storedCount++
			if mem.AuditID != "a-1" {
				t.Errorf("expected audit_id=a-1, got %q", mem.AuditID)
			}
			if mem.RemediationStatus != "open" {
				t.Errorf("expected remediation_status=open, got %q", mem.RemediationStatus)
			}
			return nil
		},
	}
	svc := newMemoryServiceWithMock(repo)

	findings := []model.Finding{
		{
			Title:          "SQL Injection",
			Category:       "injection",
			AgentType:      "owasp",
			Severity:       model.SeverityHigh,
			Description:    "Found SQL injection vulnerability",
			FilePath:       "/src/db.go",
			Recommendation: "Use parameterized queries",
		},
		{
			Title:       "Missing CSRF",
			Category:    "csrf",
			AgentType:   "owasp",
			Severity:    model.SeverityMedium,
			Description: "No CSRF protection",
			FilePath:    "/src/handler.go",
		},
	}

	err := svc.StoreFindingsAsMemories("a-1", "/project", findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if storedCount != 2 {
		t.Errorf("expected 2 stored memories, got %d", storedCount)
	}
}

func TestMemoryService_StoreFindingsAsMemories_Error(t *testing.T) {
	repoErr := errors.New("store failed")
	repo := &repository.MockMemoryRepository{
		StoreMemoryFn: func(mem *model.AuditMemory) error {
			return repoErr
		},
	}
	svc := newMemoryServiceWithMock(repo)

	err := svc.StoreFindingsAsMemories("a-1", "/src", []model.Finding{{Title: "test"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped repo error, got %v", err)
	}
}

func TestExtractKeywords(t *testing.T) {
	tests := []struct {
		name        string
		title       string
		description string
		wantMin     int
		wantMax     int
		wantAbsent  []string // stop words that should be filtered
	}{
		{
			name:        "filters stop words",
			title:       "The SQL injection is a vulnerability",
			description: "It can be used to bypass authentication",
			wantMin:     3,
			wantMax:     15,
			wantAbsent:  []string{"the", "is", "a", "it", "can", "be", "to"},
		},
		{
			name:        "limits to 15",
			title:       "word1 word2 word3 word4 word5 word6 word7 word8",
			description: "word9 word10 word11 word12 word13 word14 word15 word16 word17",
			wantMin:     15,
			wantMax:     15,
		},
		{
			name:        "deduplicates",
			title:       "sql sql sql injection injection",
			description: "sql injection found",
			wantMin:     2,
			wantMax:     3,
		},
		{
			name:        "filters short words",
			title:       "ab cd ef gh ij",
			description: "kl mn op vulnerability",
			wantMin:     1,
			wantMax:     1,
		},
		{
			name:        "empty input",
			title:       "",
			description: "",
			wantMin:     0,
			wantMax:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractKeywords(tt.title, tt.description)
			if len(result) < tt.wantMin {
				t.Errorf("got %d keywords (min %d): %v", len(result), tt.wantMin, result)
			}
			if len(result) > tt.wantMax {
				t.Errorf("got %d keywords (max %d): %v", len(result), tt.wantMax, result)
			}
			for _, absent := range tt.wantAbsent {
				for _, kw := range result {
					if kw == absent {
						t.Errorf("stop word %q should be filtered, found in %v", absent, result)
					}
				}
			}
		})
	}
}

func TestBuildEmbeddingText(t *testing.T) {
	mem := &model.AuditMemory{
		Title:         "SQL Injection",
		Content:       "Found vulnerability",
		Category:      "injection",
		Severity:      model.SeverityHigh,
		ComplianceRef: "CC6.1",
		FilePaths:     []string{"/src/db.go", "/src/handler.go"},
	}

	text := buildEmbeddingText(mem)
	if !strings.Contains(text, "SQL Injection") {
		t.Error("expected title in embedding text")
	}
	if !strings.Contains(text, "Found vulnerability") {
		t.Error("expected content in embedding text")
	}
	if !strings.Contains(text, "Category: injection") {
		t.Error("expected category in embedding text")
	}
	if !strings.Contains(text, "Severity: high") {
		t.Error("expected severity in embedding text")
	}
	if !strings.Contains(text, "Compliance: CC6.1") {
		t.Error("expected compliance ref in embedding text")
	}
	if !strings.Contains(text, "Files: /src/db.go, /src/handler.go") {
		t.Error("expected file paths in embedding text")
	}
}

func TestBuildEmbeddingText_Minimal(t *testing.T) {
	mem := &model.AuditMemory{
		Title:    "Title",
		Content:  "Content",
		Category: "cat",
		Severity: model.SeverityLow,
	}

	text := buildEmbeddingText(mem)
	if strings.Contains(text, "Compliance:") {
		t.Error("should not include compliance when empty")
	}
	if strings.Contains(text, "Files:") {
		t.Error("should not include files when empty")
	}
}

func TestInferRelationType(t *testing.T) {
	tests := []struct {
		name   string
		source *model.AuditMemory
		target *model.AuditMemory
		want   string
	}{
		{
			name:   "same finding type",
			source: &model.AuditMemory{FindingType: "injection", Category: "owasp"},
			target: &model.AuditMemory{FindingType: "injection", Category: "soc2"},
			want:   "same_issue",
		},
		{
			name:   "same category different type",
			source: &model.AuditMemory{FindingType: "xss", Category: "owasp"},
			target: &model.AuditMemory{FindingType: "injection", Category: "owasp"},
			want:   "related_compliance",
		},
		{
			name:   "different type and category",
			source: &model.AuditMemory{FindingType: "xss", Category: "owasp"},
			target: &model.AuditMemory{FindingType: "timeout", Category: "chaos"},
			want:   "similar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferRelationType(tt.source, tt.target)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateMemoryID_Deterministic(t *testing.T) {
	id1 := generateMemoryID("a-1", "SQL Injection", "injection")
	id2 := generateMemoryID("a-1", "SQL Injection", "injection")
	if id1 != id2 {
		t.Errorf("expected deterministic IDs, got %q and %q", id1, id2)
	}
}

func TestGenerateMemoryID_DifferentInputs(t *testing.T) {
	id1 := generateMemoryID("a-1", "SQL Injection", "injection")
	id2 := generateMemoryID("a-2", "SQL Injection", "injection")
	if id1 == id2 {
		t.Error("expected different IDs for different audit IDs")
	}
}

func TestGenerateMemoryID_Format(t *testing.T) {
	id := generateMemoryID("audit", "title", "type")
	if len(id) != 32 {
		t.Errorf("expected 32 hex chars (md5), got %d: %s", len(id), id)
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character in id: %c", c)
		}
	}
}

// newEmbeddingServer creates a test HTTP server that mimics the OpenAI embedding API.
func newEmbeddingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": []map[string]interface{}{
				{"embedding": []float64{0.1, 0.2, 0.3, 0.4, 0.5}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func newMemoryServiceWithEmbedder(repo *repository.MockMemoryRepository, baseURL string) *memoryService {
	return &memoryService{
		repo: repo,
		embedder: &embedding.Client{},
	}
}

func TestNewMemoryService_Constructor(t *testing.T) {
	repo := &repository.MockMemoryRepository{}
	svc := NewMemoryService(repo)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestMemoryService_EmbedAndLink_NotAvailable(t *testing.T) {
	repo := &repository.MockMemoryRepository{}
	svc := newMemoryServiceWithMock(repo)

	mem := &model.AuditMemory{
		ID:       "m-1",
		Title:    "Test",
		Content:  "Content",
		Category: "cat",
		Severity: model.SeverityLow,
	}
	// Should not panic when embedder is not available
	svc.embedAndLink(mem)
}

func TestMemoryService_EmbedAndLink_WithEmbedder(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	var storedEmbedding bool
	var storedEdges int
	repo := &repository.MockMemoryRepository{
		StoreEmbeddingFn: func(id string, emb []float32) error {
			storedEmbedding = true
			return nil
		},
		FindSimilarByVectorFn: func(excludeID string, emb []float32, limit int) ([]model.AuditMemory, error) {
			return []model.AuditMemory{
				{ID: "m-2", Similarity: 0.9, FindingType: "injection", Category: "owasp"},
			}, nil
		},
		StoreEdgeFn: func(e *model.MemoryEdge) error {
			storedEdges++
			return nil
		},
	}

	// Create a client that points to our test server
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{
		ID:       "m-1",
		Title:    "SQL Injection",
		Content:  "Found vulnerability",
		Category: "injection",
		Severity: model.SeverityHigh,
	}
	svc.embedAndLink(mem)

	if !storedEmbedding {
		t.Error("expected embedding to be stored")
	}
	if storedEdges != 1 {
		t.Errorf("expected 1 edge, got %d", storedEdges)
	}
}

func TestMemoryService_EmbedAndLink_EmbedError(t *testing.T) {
	// Server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprintf(w, "embedding error")
	}))
	defer server.Close()

	repo := &repository.MockMemoryRepository{}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{ID: "m-1", Title: "Test"}
	// Should not panic on embed error
	svc.embedAndLink(mem)
}

func TestMemoryService_EmbedAndLink_StoreEmbeddingError(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	repo := &repository.MockMemoryRepository{
		StoreEmbeddingFn: func(id string, emb []float32) error {
			return errors.New("store failed")
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{ID: "m-1", Title: "Test"}
	// Should not panic
	svc.embedAndLink(mem)
}

func TestMemoryService_EmbedAndLink_FindSimilarError(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	repo := &repository.MockMemoryRepository{
		StoreEmbeddingFn: func(id string, emb []float32) error { return nil },
		FindSimilarByVectorFn: func(excludeID string, emb []float32, limit int) ([]model.AuditMemory, error) {
			return nil, errors.New("find similar failed")
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{ID: "m-1", Title: "Test"}
	// Should not panic
	svc.embedAndLink(mem)
}

func TestMemoryService_EmbedAndLink_BelowThreshold(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	storeEdgeCalled := false
	repo := &repository.MockMemoryRepository{
		StoreEmbeddingFn: func(id string, emb []float32) error { return nil },
		FindSimilarByVectorFn: func(excludeID string, emb []float32, limit int) ([]model.AuditMemory, error) {
			return []model.AuditMemory{
				{ID: "m-2", Similarity: 0.5}, // below threshold
			}, nil
		},
		StoreEdgeFn: func(e *model.MemoryEdge) error {
			storeEdgeCalled = true
			return nil
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{ID: "m-1", Title: "Test"}
	svc.embedAndLink(mem)

	if storeEdgeCalled {
		t.Error("should not store edge when below threshold")
	}
}

func TestMemoryService_EmbedAndLink_StoreEdgeError(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	repo := &repository.MockMemoryRepository{
		StoreEmbeddingFn: func(id string, emb []float32) error { return nil },
		FindSimilarByVectorFn: func(excludeID string, emb []float32, limit int) ([]model.AuditMemory, error) {
			return []model.AuditMemory{
				{ID: "m-2", Similarity: 0.9, FindingType: "injection"},
			}, nil
		},
		StoreEdgeFn: func(e *model.MemoryEdge) error {
			return errors.New("store edge failed")
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{ID: "m-1", Title: "Test", FindingType: "injection"}
	// Should not panic on edge store error
	svc.embedAndLink(mem)
}

func TestMemoryService_Search_WithEmbedder(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	var gotEmbedding []float32
	repo := &repository.MockMemoryRepository{
		SearchMemoriesFn: func(query string, emb []float32, limit int) ([]model.AuditMemory, error) {
			gotEmbedding = emb
			return []model.AuditMemory{{ID: "m-1"}}, nil
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	results, err := svc.Search(&model.MemorySearchRequest{Query: "sql injection", Limit: 10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if gotEmbedding == nil {
		t.Error("expected embedding to be passed to repo")
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryService_Search_EmbedError_FallsBackToText(t *testing.T) {
	// Server that returns errors for embedding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	var gotEmbedding []float32
	repo := &repository.MockMemoryRepository{
		SearchMemoriesFn: func(query string, emb []float32, limit int) ([]model.AuditMemory, error) {
			gotEmbedding = emb
			return []model.AuditMemory{{ID: "m-1"}}, nil
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	results, err := svc.Search(&model.MemorySearchRequest{Query: "test", Limit: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if gotEmbedding != nil {
		t.Error("expected nil embedding on embed error fallback")
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestMemoryService_Store_TriggersEmbedAsync(t *testing.T) {
	server := newEmbeddingServer(t)
	defer server.Close()

	embeddingStored := make(chan bool, 1)
	repo := &repository.MockMemoryRepository{
		StoreMemoryFn: func(mem *model.AuditMemory) error { return nil },
		StoreEmbeddingFn: func(id string, emb []float32) error {
			embeddingStored <- true
			return nil
		},
		FindSimilarByVectorFn: func(excludeID string, emb []float32, limit int) ([]model.AuditMemory, error) {
			return nil, nil
		},
	}

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("VULTURE_EMBEDDING_URL", server.URL)

	svc := &memoryService{
		repo:     repo,
		embedder: embedding.New(),
	}

	mem := &model.AuditMemory{
		ID:       "m-async",
		Title:    "Test",
		Content:  "Content",
		Severity: model.SeverityLow,
	}
	err := svc.Store(mem)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// Wait for async embedding to complete
	select {
	case <-embeddingStored:
		// success
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for async embedding")
	}
}

func TestMemoryService_GetWithEdges_MemoryRepoError(t *testing.T) {
	repoErr := errors.New("db error")
	repo := &repository.MockMemoryRepository{
		GetMemoryFn: func(id string) (*model.AuditMemory, error) {
			return nil, repoErr
		},
	}
	svc := newMemoryServiceWithMock(repo)

	_, err := svc.GetWithEdges("m-1")
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repo error, got %v", err)
	}
}
