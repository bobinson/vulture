package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

func TestStreamHandlerMissingAuditID(t *testing.T) {
	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, nil)

	req := httptest.NewRequest("GET", "/api/audits//stream", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestStreamHandlerAuditNotFound(t *testing.T) {
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return nil, service.ErrNotFound
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	req := httptest.NewRequest("GET", "/api/audits/missing/stream", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestStreamHandlerAuditError(t *testing.T) {
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return nil, errTest
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	req := httptest.NewRequest("GET", "/api/audits/err/stream", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestParseSnapshot(t *testing.T) {
	snapshot := json.RawMessage(`{
		"findings": [
			{"title": "SQL Injection", "severity": "high", "file_path": "/db.py"},
			{"title": "XSS", "severity": "medium", "file_path": "/web.js", "id": "existing-id"}
		],
		"score": 75.5
	}`)

	var findings []model.Finding
	scores := map[string]int{}

	parseSnapshot(snapshot, "audit-1", "owasp", &findings, scores)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Title != "SQL Injection" {
		t.Errorf("expected SQL Injection, got %s", findings[0].Title)
	}
	if findings[0].AuditID != "audit-1" {
		t.Errorf("expected audit-1, got %s", findings[0].AuditID)
	}
	if findings[0].AgentType != "owasp" {
		t.Errorf("expected owasp, got %s", findings[0].AgentType)
	}
	if findings[0].ID == "" {
		t.Error("expected auto-generated ID for finding without ID")
	}
	if findings[1].ID != "existing-id" {
		t.Errorf("expected existing-id preserved, got %s", findings[1].ID)
	}
	if scores["owasp"] != 75 {
		t.Errorf("expected score 75, got %d", scores["owasp"])
	}
}

func TestParseSnapshotBadJSON(t *testing.T) {
	snapshot := json.RawMessage(`{invalid json`)
	var findings []model.Finding
	scores := map[string]int{}

	// Should not panic
	parseSnapshot(snapshot, "audit-1", "owasp", &findings, scores)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for bad JSON, got %d", len(findings))
	}
}

func TestParseSnapshotEmptyAgentType(t *testing.T) {
	snapshot := json.RawMessage(`{"findings":[],"score":80}`)
	var findings []model.Finding
	scores := map[string]int{}

	parseSnapshot(snapshot, "audit-1", "", &findings, scores)

	// Empty agent type should not add to scores
	if _, ok := scores[""]; ok {
		t.Error("empty agent type should not be added to scores")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		max    int
		expect string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is longer than ten", 10, "this is lo..."},
		{"", 5, ""},
	}
	for _, tc := range tests {
		got := truncate(tc.input, tc.max)
		if got != tc.expect {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.max, got, tc.expect)
		}
	}
}

func TestGenerateFindingID(t *testing.T) {
	id1 := generateFindingID("audit-1", "SQL Injection", "/db.py", 0)
	id2 := generateFindingID("audit-1", "SQL Injection", "/db.py", 0)
	id3 := generateFindingID("audit-2", "SQL Injection", "/db.py", 0)
	id4 := generateFindingID("audit-1", "SQL Injection", "/db.py", 1)

	if id1 != id2 {
		t.Errorf("same inputs should produce same ID: %s != %s", id1, id2)
	}
	if id1 == id3 {
		t.Error("different audit IDs should produce different finding IDs")
	}
	if id1 == id4 {
		t.Error("different indices should produce different finding IDs")
	}
	if len(id1) != 32 {
		t.Errorf("expected 32 char hex, got %d: %s", len(id1), id1)
	}
}

func TestExtractStreamAuditID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/audits/abc123/stream", "abc123"},
		{"/api/audits//stream", ""},
		{"/api/audits/xyz", "xyz"},
	}
	for _, tc := range tests {
		got := extractStreamAuditID(tc.path)
		if got != tc.want {
			t.Errorf("extractStreamAuditID(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestFirstOrEmpty(t *testing.T) {
	if got := firstOrEmpty([]string{"a", "b"}); got != "a" {
		t.Errorf("expected 'a', got %q", got)
	}
	if got := firstOrEmpty([]string{}); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	if got := firstOrEmpty(nil); got != "" {
		t.Errorf("expected empty for nil, got %q", got)
	}
}

func TestLoadPriorFindingsNoMemoryService(t *testing.T) {
	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, nil)
	result := h.loadPriorFindings("/code", []string{"owasp"})
	if result != nil {
		t.Errorf("expected nil when no memory service, got %v", result)
	}
}

func TestLoadPriorFindingsWithMemories(t *testing.T) {
	memSvc := &mockMemoryService{
		listByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			if agentType == "owasp" {
				return []model.AuditMemory{
					{ID: "m-1", Title: "SQL Injection", Severity: "high", FilePaths: []string{"/db.py"}, RemediationStatus: "open"},
				}, nil
			}
			return nil, nil
		},
	}
	agents := map[string]config.AgentConfig{}
	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, agents)
	h.SetMemoryService(memSvc)

	result := h.loadPriorFindings("/code", []string{"owasp", "chaos"})

	if len(result["owasp"]) != 1 {
		t.Fatalf("expected 1 owasp prior finding, got %d", len(result["owasp"]))
	}
	if result["owasp"][0].Title != "SQL Injection" {
		t.Errorf("expected SQL Injection, got %s", result["owasp"][0].Title)
	}
	if _, ok := result["chaos"]; ok {
		t.Error("chaos should not be in result since no memories returned")
	}
}

func TestLoadPriorFindingsWithError(t *testing.T) {
	memSvc := &mockMemoryService{
		listByCodebasePathFn: func(path, agentType string, limit int) ([]model.AuditMemory, error) {
			return nil, errTest
		},
	}
	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, nil)
	h.SetMemoryService(memSvc)

	result := h.loadPriorFindings("/code", []string{"owasp"})
	// Errors should be silently ignored
	if len(result) != 0 {
		t.Errorf("expected empty result on error, got %d", len(result))
	}
}

func TestSetMemoryService(t *testing.T) {
	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, nil)
	if h.memorySvc != nil {
		t.Fatal("expected nil memory service initially")
	}

	memSvc := &mockMemoryService{}
	h.SetMemoryService(memSvc)
	if h.memorySvc == nil {
		t.Fatal("expected non-nil memory service after set")
	}
}

func TestStreamHandlerReplayCompleted(t *testing.T) {
	findings := []model.Finding{
		{ID: "f-1", Title: "Bug", AgentType: "owasp"},
	}
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{
				ID:       id,
				Status:   model.AuditStatusCompleted,
				Types:    []string{"owasp"},
				Findings: findings,
				Scores:   map[string]int{"owasp": 85},
			}, nil
		},
	}
	h := NewStreamHandler(svc, &mockSourceService{}, &mockStreamService{}, nil)

	// Use a ResponseWriter that implements Flusher for SSE
	req := httptest.NewRequest("GET", "/api/audits/a-1/stream", nil)
	w := &flushableRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if body == "" {
		t.Fatal("expected SSE events in body")
	}
}

// flushableRecorder implements http.Flusher for SSE testing.
type flushableRecorder struct {
	*httptest.ResponseRecorder
}

func (fr *flushableRecorder) Flush() {}
