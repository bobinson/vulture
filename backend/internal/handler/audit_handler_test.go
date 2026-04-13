package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

var errTest = errors.New("test error")

// --- Mock implementations ---

type mockAuditService struct {
	createFn                   func(req *model.AuditRequest) (*model.Audit, error)
	getFn                      func(id string) (*model.Audit, error)
	updateFn                   func(audit *model.Audit) error
	saveFindingsFn             func(auditID string, findings []model.Finding) error
	listFn                     func(limit, offset int) ([]model.Audit, error)
	statsFn                    func() (*model.DashboardStats, error)
	getCachedAuditFn           func(sourceID string, types []string) (*model.Audit, error)
	findSourceFn               func(path string) (*model.Source, error)
	getPreviousCompletedFn     func(sourceID string, types []string, excludeAuditID string) (*model.Audit, error)
	listAuditsBySourcePathFn   func(sourcePath string, limit, offset int) ([]model.Audit, error)
}

func (m *mockAuditService) Create(req *model.AuditRequest) (*model.Audit, error) {
	if m.createFn != nil {
		return m.createFn(req)
	}
	return &model.Audit{ID: "a-1"}, nil
}
func (m *mockAuditService) Get(id string) (*model.Audit, error) {
	if m.getFn != nil {
		return m.getFn(id)
	}
	return &model.Audit{ID: id}, nil
}
func (m *mockAuditService) Update(audit *model.Audit) error {
	if m.updateFn != nil {
		return m.updateFn(audit)
	}
	return nil
}
func (m *mockAuditService) SaveFindings(auditID string, findings []model.Finding) error {
	if m.saveFindingsFn != nil {
		return m.saveFindingsFn(auditID, findings)
	}
	return nil
}
func (m *mockAuditService) List(limit, offset int) ([]model.Audit, error) {
	if m.listFn != nil {
		return m.listFn(limit, offset)
	}
	return []model.Audit{}, nil
}
func (m *mockAuditService) Stats() (*model.DashboardStats, error) {
	if m.statsFn != nil {
		return m.statsFn()
	}
	return &model.DashboardStats{}, nil
}
func (m *mockAuditService) GetCachedAudit(sourceID string, types []string) (*model.Audit, error) {
	if m.getCachedAuditFn != nil {
		return m.getCachedAuditFn(sourceID, types)
	}
	return nil, nil
}
func (m *mockAuditService) FindSourceByPath(path string) (*model.Source, error) {
	if m.findSourceFn != nil {
		return m.findSourceFn(path)
	}
	return nil, nil
}
func (m *mockAuditService) GetPreviousCompletedAudit(sourceID string, types []string, excludeAuditID string) (*model.Audit, error) {
	if m.getPreviousCompletedFn != nil {
		return m.getPreviousCompletedFn(sourceID, types, excludeAuditID)
	}
	return nil, nil
}
func (m *mockAuditService) ListAuditsBySourcePath(sourcePath string, limit, offset int) ([]model.Audit, error) {
	if m.listAuditsBySourcePathFn != nil {
		return m.listAuditsBySourcePathFn(sourcePath, limit, offset)
	}
	return nil, nil
}

type mockSourceService struct {
	ingestFn func(ctx context.Context, req *model.SourceRequest) (*model.Source, error)
	getFn    func(id string) (*model.Source, error)
}

func (m *mockSourceService) Ingest(ctx context.Context, req *model.SourceRequest) (*model.Source, error) {
	if m.ingestFn != nil {
		return m.ingestFn(ctx, req)
	}
	return &model.Source{ID: "s-1", Type: model.SourceType(req.Type)}, nil
}
func (m *mockSourceService) Get(id string) (*model.Source, error) {
	if m.getFn != nil {
		return m.getFn(id)
	}
	return &model.Source{ID: id, Path: "/test"}, nil
}

type mockMemoryService struct {
	storeFn              func(mem *model.AuditMemory) error
	searchFn             func(req *model.MemorySearchRequest) ([]model.AuditMemory, error)
	getFn                func(id string) (*model.AuditMemory, error)
	getWithEdgesFn       func(id string) (*model.MemoryWithEdges, error)
	updateRemFn          func(id, status, notes string) error
	listByAuditFn        func(auditID string) ([]model.AuditMemory, error)
	listByCodebasePathFn      func(path, agentType string, limit int) ([]model.AuditMemory, error)
	listByCodebasePathMultiFn func(path string, agentTypes []string, limit int) (map[string][]model.AuditMemory, error)
	listRecentFn              func(limit int) ([]model.AuditMemory, error)
	storeFindingsFn      func(auditID, sourcePath string, findings []model.Finding) error
	getEdgesFn           func(memoryID string) ([]model.MemoryEdge, error)
}

func (m *mockMemoryService) Store(mem *model.AuditMemory) error {
	if m.storeFn != nil {
		return m.storeFn(mem)
	}
	return nil
}
func (m *mockMemoryService) Search(req *model.MemorySearchRequest) ([]model.AuditMemory, error) {
	if m.searchFn != nil {
		return m.searchFn(req)
	}
	return []model.AuditMemory{}, nil
}
func (m *mockMemoryService) Get(id string) (*model.AuditMemory, error) {
	if m.getFn != nil {
		return m.getFn(id)
	}
	return &model.AuditMemory{ID: id}, nil
}
func (m *mockMemoryService) GetWithEdges(id string) (*model.MemoryWithEdges, error) {
	if m.getWithEdgesFn != nil {
		return m.getWithEdgesFn(id)
	}
	return &model.MemoryWithEdges{AuditMemory: model.AuditMemory{ID: id}}, nil
}
func (m *mockMemoryService) UpdateRemediation(id, status, notes string) error {
	if m.updateRemFn != nil {
		return m.updateRemFn(id, status, notes)
	}
	return nil
}
func (m *mockMemoryService) ListByAudit(auditID string) ([]model.AuditMemory, error) {
	if m.listByAuditFn != nil {
		return m.listByAuditFn(auditID)
	}
	return []model.AuditMemory{}, nil
}
func (m *mockMemoryService) ListByCodebasePath(path, agentType string, limit int) ([]model.AuditMemory, error) {
	if m.listByCodebasePathFn != nil {
		return m.listByCodebasePathFn(path, agentType, limit)
	}
	return []model.AuditMemory{}, nil
}
func (m *mockMemoryService) ListByCodebasePathMulti(path string, agentTypes []string, limit int) (map[string][]model.AuditMemory, error) {
	if m.listByCodebasePathMultiFn != nil {
		return m.listByCodebasePathMultiFn(path, agentTypes, limit)
	}
	return nil, nil
}
func (m *mockMemoryService) ListRecent(limit int) ([]model.AuditMemory, error) {
	if m.listRecentFn != nil {
		return m.listRecentFn(limit)
	}
	return []model.AuditMemory{}, nil
}
func (m *mockMemoryService) StoreFindingsAsMemories(auditID, sourcePath string, findings []model.Finding) error {
	if m.storeFindingsFn != nil {
		return m.storeFindingsFn(auditID, sourcePath, findings)
	}
	return nil
}
func (m *mockMemoryService) GetEdges(memoryID string) ([]model.MemoryEdge, error) {
	if m.getEdgesFn != nil {
		return m.getEdgesFn(memoryID)
	}
	return []model.MemoryEdge{}, nil
}

type mockStreamService struct {
	streamFn            func(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, eventCh chan<- *model.AgUIEvent)
	streamWithContextFn func(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent)
}

func (m *mockStreamService) Stream(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, eventCh chan<- *model.AgUIEvent) {
	if m.streamFn != nil {
		m.streamFn(ctx, audit, sourcePath, agents, eventCh)
		return
	}
	close(eventCh)
}
func (m *mockStreamService) StreamWithContext(ctx context.Context, audit *model.Audit, sourcePath string, agents map[string]config.AgentConfig, priorByAgent map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
	if m.streamWithContextFn != nil {
		m.streamWithContextFn(ctx, audit, sourcePath, agents, priorByAgent, eventCh)
		return
	}
	close(eventCh)
}

// --- AuditHandler Tests ---

func TestAuditHandlerCreate(t *testing.T) {
	svc := &mockAuditService{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			return &model.Audit{ID: "a-1", SourceID: req.SourceID, Types: req.Types}, nil
		},
	}
	h := NewAuditHandler(svc)

	body := `{"source_id":"s-1","types":["owasp","chaos"]}`
	req := httptest.NewRequest("POST", "/api/audits", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var audit model.Audit
	json.NewDecoder(w.Body).Decode(&audit)
	if audit.ID != "a-1" {
		t.Fatalf("expected a-1, got %s", audit.ID)
	}
}

func TestAuditHandlerCreateBadJSON(t *testing.T) {
	h := NewAuditHandler(&mockAuditService{})
	req := httptest.NewRequest("POST", "/api/audits", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAuditHandlerCreateNotFound(t *testing.T) {
	svc := &mockAuditService{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			return nil, service.ErrNotFound
		},
	}
	h := NewAuditHandler(svc)

	body := `{"source_id":"missing","types":["owasp"]}`
	req := httptest.NewRequest("POST", "/api/audits", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestAuditHandlerCreateInternalError(t *testing.T) {
	svc := &mockAuditService{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			return nil, errTest
		},
	}
	h := NewAuditHandler(svc)

	body := `{"source_id":"s-1","types":["owasp"]}`
	req := httptest.NewRequest("POST", "/api/audits", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestAuditHandlerList(t *testing.T) {
	svc := &mockAuditService{
		listFn: func(limit, offset int) ([]model.Audit, error) {
			if limit != 10 || offset != 5 {
				t.Errorf("expected limit=10 offset=5, got limit=%d offset=%d", limit, offset)
			}
			return []model.Audit{{ID: "a-1"}, {ID: "a-2"}}, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits?limit=10&offset=5", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var audits []model.Audit
	json.NewDecoder(w.Body).Decode(&audits)
	if len(audits) != 2 {
		t.Fatalf("expected 2 audits, got %d", len(audits))
	}
}

func TestAuditHandlerListDefaultParams(t *testing.T) {
	svc := &mockAuditService{
		listFn: func(limit, offset int) ([]model.Audit, error) {
			if limit != 20 || offset != 0 {
				t.Errorf("expected default limit=20 offset=0, got limit=%d offset=%d", limit, offset)
			}
			return nil, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// nil result should be converted to empty array
	var audits []model.Audit
	json.NewDecoder(w.Body).Decode(&audits)
	if len(audits) != 0 {
		t.Fatalf("expected 0 audits, got %d", len(audits))
	}
}

func TestAuditHandlerListError(t *testing.T) {
	svc := &mockAuditService{
		listFn: func(limit, offset int) ([]model.Audit, error) {
			return nil, errTest
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestAuditHandlerStats(t *testing.T) {
	svc := &mockAuditService{
		statsFn: func() (*model.DashboardStats, error) {
			return &model.DashboardStats{TotalFindings: 42, AuditsRun: 5}, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	h.Stats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuditHandlerStatsError(t *testing.T) {
	svc := &mockAuditService{
		statsFn: func() (*model.DashboardStats, error) {
			return nil, errTest
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	h.Stats(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestAuditHandlerGet(t *testing.T) {
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{ID: id, Status: model.AuditStatusCompleted}, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/abc123", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuditHandlerGetMissingID(t *testing.T) {
	h := NewAuditHandler(&mockAuditService{})

	req := httptest.NewRequest("GET", "/api/audits/", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAuditHandlerGetNotFound(t *testing.T) {
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return nil, service.ErrNotFound
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/missing", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestAuditHandlerGetInternalError(t *testing.T) {
	svc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return nil, errTest
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/err", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestAuditHandlerCachedAudit(t *testing.T) {
	svc := &mockAuditService{
		getCachedAuditFn: func(sourceID string, types []string) (*model.Audit, error) {
			return &model.Audit{ID: "cached-1"}, nil
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/cache?source_id=s-1&types=owasp,chaos", nil)
	w := httptest.NewRecorder()
	h.CachedAudit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["cached"] != true {
		t.Fatalf("expected cached=true, got %v", result["cached"])
	}
}

func TestAuditHandlerCachedAuditMissing(t *testing.T) {
	h := NewAuditHandler(&mockAuditService{})

	req := httptest.NewRequest("GET", "/api/audits/cache?source_id=s-1&types=owasp", nil)
	w := httptest.NewRecorder()
	h.CachedAudit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	if result["cached"] != false {
		t.Fatalf("expected cached=false, got %v", result["cached"])
	}
}

func TestAuditHandlerCachedAuditBadParams(t *testing.T) {
	h := NewAuditHandler(&mockAuditService{})

	// Missing both params
	req := httptest.NewRequest("GET", "/api/audits/cache", nil)
	w := httptest.NewRecorder()
	h.CachedAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Missing types
	req = httptest.NewRequest("GET", "/api/audits/cache?source_id=s-1", nil)
	w = httptest.NewRecorder()
	h.CachedAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAuditHandlerCachedAuditError(t *testing.T) {
	svc := &mockAuditService{
		getCachedAuditFn: func(sourceID string, types []string) (*model.Audit, error) {
			return nil, errTest
		},
	}
	h := NewAuditHandler(svc)

	req := httptest.NewRequest("GET", "/api/audits/cache?source_id=s-1&types=owasp", nil)
	w := httptest.NewRecorder()
	h.CachedAudit(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestQueryInt(t *testing.T) {
	tests := []struct {
		url      string
		key      string
		fallback int
		want     int
	}{
		{"/api?limit=10", "limit", 20, 10},
		{"/api", "limit", 20, 20},
		{"/api?limit=abc", "limit", 20, 20},
		{"/api?limit=0", "limit", 20, 0},
	}
	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.url, nil)
		got := queryInt(req, tc.key, tc.fallback)
		if got != tc.want {
			t.Errorf("queryInt(%s, %s, %d) = %d, want %d", tc.url, tc.key, tc.fallback, got, tc.want)
		}
	}
}
