package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

func TestCompareWithPreviousAudit(t *testing.T) {
	now := time.Now().UTC()
	prev := &model.Audit{
		ID:          "prev-1",
		SourceID:    "s-1",
		Types:       []string{"cwe"},
		Status:      model.AuditStatusCompleted,
		CompletedAt: &now,
		Findings: []model.Finding{
			{Fingerprint: "fp-1", Title: "SQL Injection", Severity: model.SeverityHigh, FilePath: "/db.py", AgentType: "cwe"},
			{Fingerprint: "fp-2", Title: "XSS", Severity: model.SeverityMedium, FilePath: "/web.js", AgentType: "cwe"},
			{Fingerprint: "fp-3", Title: "Fixed Bug", Severity: model.SeverityLow, FilePath: "/old.py", AgentType: "cwe"},
		},
	}
	current := &model.Audit{
		ID:       "curr-1",
		SourceID: "s-1",
		Types:    []string{"cwe"},
		Status:   model.AuditStatusCompleted,
		Findings: []model.Finding{
			{Fingerprint: "fp-1", Title: "SQL Injection", Severity: model.SeverityHigh, FilePath: "/db.py", AgentType: "cwe"},
			{Fingerprint: "fp-2", Title: "XSS", Severity: model.SeverityCritical, FilePath: "/web.js", AgentType: "cwe"},
			{Fingerprint: "fp-4", Title: "New Bug", Severity: model.SeverityHigh, FilePath: "/new.py", AgentType: "cwe"},
		},
	}

	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			if id == "curr-1" {
				return current, nil
			}
			return nil, service.ErrNotFound
		},
		getPreviousCompletedFn: func(sourceID string, types []string, excludeID string) (*model.Audit, error) {
			return prev, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/curr-1/comparison", nil)
	w := httptest.NewRecorder()
	h.Compare(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var comp model.AuditComparison
	if err := json.NewDecoder(w.Body).Decode(&comp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if !comp.HasPrevious {
		t.Fatal("expected has_previous=true")
	}
	if comp.PreviousAuditID != "prev-1" {
		t.Errorf("expected previous_audit_id=prev-1, got %s", comp.PreviousAuditID)
	}
	if comp.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", comp.NewCount)
	}
	if comp.FixedCount != 1 {
		t.Errorf("expected 1 fixed finding, got %d", comp.FixedCount)
	}
	if comp.PersistentCount != 1 {
		t.Errorf("expected 1 persistent finding, got %d", comp.PersistentCount)
	}
	if comp.ChangedCount != 1 {
		t.Errorf("expected 1 changed finding, got %d", comp.ChangedCount)
	}
	if comp.CurrentFindingsCount != 3 {
		t.Errorf("expected 3 current findings, got %d", comp.CurrentFindingsCount)
	}
	if comp.PreviousFindingsCount != 3 {
		t.Errorf("expected 3 previous findings, got %d", comp.PreviousFindingsCount)
	}
}

func TestCompareNoPreviousAudit(t *testing.T) {
	current := &model.Audit{
		ID:       "curr-1",
		SourceID: "s-1",
		Types:    []string{"cwe"},
		Status:   model.AuditStatusCompleted,
		Findings: []model.Finding{
			{Fingerprint: "fp-1", Title: "Bug", Severity: model.SeverityHigh},
		},
	}

	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return current, nil
		},
		getPreviousCompletedFn: func(sourceID string, types []string, excludeID string) (*model.Audit, error) {
			return nil, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/curr-1/comparison", nil)
	w := httptest.NewRecorder()
	h.Compare(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var comp model.AuditComparison
	if err := json.NewDecoder(w.Body).Decode(&comp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if comp.HasPrevious {
		t.Fatal("expected has_previous=false")
	}
	if comp.CurrentFindingsCount != 1 {
		t.Errorf("expected 1 current finding, got %d", comp.CurrentFindingsCount)
	}
}

func TestCompareAuditNotFound(t *testing.T) {
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return nil, service.ErrNotFound
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/missing/comparison", nil)
	w := httptest.NewRecorder()
	h.Compare(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCompareMissingAuditID(t *testing.T) {
	h := NewAuditHandler(&mockAuditService{})

	req := httptest.NewRequest("GET", "/api/audits//comparison", nil)
	w := httptest.NewRecorder()
	h.Compare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestBuildComparisonChangedSeverity(t *testing.T) {
	current := &model.Audit{
		Findings: []model.Finding{
			{Fingerprint: "fp-1", Title: "Bug", Severity: model.SeverityCritical, FilePath: "/a.py"},
		},
	}
	previous := &model.Audit{
		ID: "prev-1",
		Findings: []model.Finding{
			{Fingerprint: "fp-1", Title: "Bug", Severity: model.SeverityLow, FilePath: "/a.py"},
		},
	}

	comp := buildComparison(current, previous)

	if comp.ChangedCount != 1 {
		t.Errorf("expected 1 changed, got %d", comp.ChangedCount)
	}
	if len(comp.ChangedFindings) != 1 {
		t.Fatalf("expected 1 changed finding detail, got %d", len(comp.ChangedFindings))
	}
	cf := comp.ChangedFindings[0]
	if cf.OldSeverity != model.SeverityLow || cf.NewSeverity != model.SeverityCritical {
		t.Errorf("expected low→critical, got %s→%s", cf.OldSeverity, cf.NewSeverity)
	}
}

func TestDeduplicateCrossAgentSetsOrigins(t *testing.T) {
	findings := []model.Finding{
		{Title: "SQL Injection", FilePath: "/db.py", LineStart: 42, AgentType: "owasp", Severity: model.SeverityHigh},
		{Title: "SQL Injection", FilePath: "/db.py", LineStart: 42, AgentType: "cwe", Severity: model.SeverityCritical, CheckID: "cwe.89"},
		{Title: "SQL Injection", FilePath: "/db.py", LineStart: 42, AgentType: "xss", Severity: model.SeverityMedium},
		{Title: "Memory Leak", FilePath: "/mem.c", LineStart: 10, AgentType: "cwe", Severity: model.SeverityHigh},
	}

	result := deduplicateCrossAgent(findings)

	if len(result) != 2 {
		t.Fatalf("expected 2 findings after dedup, got %d", len(result))
	}

	for _, f := range result {
		if f.Title == "SQL Injection" {
			if f.AgentType != "cwe" {
				t.Errorf("expected CWE winner for SQL Injection, got %s", f.AgentType)
			}
			if len(f.CrossAgentOrigins) != 2 {
				t.Errorf("expected 2 cross-agent origins, got %d: %v", len(f.CrossAgentOrigins), f.CrossAgentOrigins)
			}
		}
		if f.Title == "Memory Leak" {
			if len(f.CrossAgentOrigins) != 0 {
				t.Errorf("unique finding should have no cross-agent origins, got %v", f.CrossAgentOrigins)
			}
		}
	}
}

func TestListAuditsWithSourcePathFilter(t *testing.T) {
	svc := &mockAuditService{
		listAuditsBySourcePathFn: func(sourcePath string, limit, offset int) ([]model.Audit, error) {
			if sourcePath != "/my/code" {
				t.Errorf("expected /my/code, got %s", sourcePath)
			}
			return []model.Audit{{ID: "a-1", SourcePath: sourcePath}}, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits?source_path=/my/code", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var audits []model.Audit
	json.NewDecoder(w.Body).Decode(&audits)
	if len(audits) != 1 || audits[0].ID != "a-1" {
		t.Fatalf("expected 1 audit with ID a-1, got %v", audits)
	}
}
