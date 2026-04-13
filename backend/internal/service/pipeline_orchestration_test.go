package service

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// --- Mocks scoped to pipeline orchestration tests ---

type mockPipelineAuditSvc struct {
	createFn func(*model.AuditRequest) (*model.Audit, error)
	getFn    func(string) (*model.Audit, error)
}

func (m *mockPipelineAuditSvc) Create(req *model.AuditRequest) (*model.Audit, error) {
	if m.createFn != nil {
		return m.createFn(req)
	}
	return &model.Audit{ID: "mock-audit"}, nil
}
func (m *mockPipelineAuditSvc) Get(id string) (*model.Audit, error) {
	if m.getFn != nil {
		return m.getFn(id)
	}
	return nil, nil
}
func (m *mockPipelineAuditSvc) Update(*model.Audit) error                                     { return nil }
func (m *mockPipelineAuditSvc) SaveFindings(string, []model.Finding) error                    { return nil }
func (m *mockPipelineAuditSvc) List(int, int) ([]model.Audit, error)                          { return nil, nil }
func (m *mockPipelineAuditSvc) Stats() (*model.DashboardStats, error)                         { return nil, nil }
func (m *mockPipelineAuditSvc) GetCachedAudit(string, []string) (*model.Audit, error)         { return nil, nil }
func (m *mockPipelineAuditSvc) FindSourceByPath(string) (*model.Source, error)                 { return nil, nil }
func (m *mockPipelineAuditSvc) GetPreviousCompletedAudit(string, []string, string) (*model.Audit, error) {
	return nil, nil
}
func (m *mockPipelineAuditSvc) ListAuditsBySourcePath(string, int, int) ([]model.Audit, error) {
	return nil, nil
}

type mockPipelineDiscoverSvc struct {
	getResultFn func(string) (*model.DiscoverResult, error)
}

func (m *mockPipelineDiscoverSvc) GetResultByAuditID(id string) (*model.DiscoverResult, error) {
	if m.getResultFn != nil {
		return m.getResultFn(id)
	}
	return nil, nil
}
func (m *mockPipelineDiscoverSvc) GetResult(string) (*model.DiscoverResult, error)       { return nil, nil }
func (m *mockPipelineDiscoverSvc) GetResultByTarget(string) (*model.DiscoverResult, error) { return nil, nil }
func (m *mockPipelineDiscoverSvc) SaveResult(*model.DiscoverResult) error                  { return nil }

// --- RED: Tests for AdvanceStage creating next audit ---

func TestAdvanceStage_CreatesNextAudit(t *testing.T) {
	pipeline := &model.Pipeline{
		ID: "p-1", TargetURL: "https://staging.example.com", SourceID: "src-1",
		Stages:      []string{"scan", "discover", "prove"},
		Config:      json.RawMessage(`{"types":["owasp"]}`),
		ScanAuditID: "audit-scan-1",
		Status:      model.PipelineStatusScanRunning,
	}
	var createdReq *model.AuditRequest
	var updatedPipeline *model.Pipeline

	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(id string) (*model.Pipeline, error) {
			if id == "audit-scan-1" {
				return pipeline, nil
			}
			return nil, nil
		},
		UpdatePipelineFn: func(p *model.Pipeline) error {
			updatedPipeline = p
			return nil
		},
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			createdReq = req
			return &model.Audit{ID: "audit-discover-1"}, nil
		},
	}
	svc := NewPipelineService(repo, auditSvc, &mockPipelineDiscoverSvc{})

	if err := svc.AdvanceStage("audit-scan-1", model.AuditStatusCompleted); err != nil {
		t.Fatalf("AdvanceStage: %v", err)
	}
	if createdReq == nil {
		t.Fatal("expected next-stage audit to be created")
	}
	if updatedPipeline == nil || updatedPipeline.DiscoverAuditID != "audit-discover-1" {
		t.Errorf("expected discover_audit_id set")
	}
	if updatedPipeline.Status != model.PipelineStatusDiscoverRunning {
		t.Errorf("expected discover_running, got %s", updatedPipeline.Status)
	}
}

func TestAdvanceStage_InjectsDiscoverIntoProve(t *testing.T) {
	pipeline := &model.Pipeline{
		ID: "p-2", TargetURL: "https://staging.example.com", SourceID: "src-1",
		Stages:          []string{"scan", "discover", "prove"},
		Config:          json.RawMessage(`{"types":["owasp"]}`),
		ScanAuditID:     "a-scan", DiscoverAuditID: "a-discover",
		Status:          model.PipelineStatusDiscoverRunning,
	}
	var createdReq *model.AuditRequest

	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(id string) (*model.Pipeline, error) {
			if id == "a-discover" {
				return pipeline, nil
			}
			return nil, nil
		},
		UpdatePipelineFn: func(*model.Pipeline) error { return nil },
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			createdReq = req
			return &model.Audit{ID: "a-prove"}, nil
		},
	}
	discoverSvc := &mockPipelineDiscoverSvc{
		getResultFn: func(string) (*model.DiscoverResult, error) {
			return &model.DiscoverResult{SiteMapJSON: `{"urls":["/api/users"]}`}, nil
		},
	}
	svc := NewPipelineService(repo, auditSvc, discoverSvc)

	if err := svc.AdvanceStage("a-discover", model.AuditStatusCompleted); err != nil {
		t.Fatalf("AdvanceStage: %v", err)
	}
	if createdReq == nil {
		t.Fatal("expected prove audit created")
	}
	var cfg map[string]interface{}
	json.Unmarshal(createdReq.Config, &cfg)
	if cfg["staging_url"] != "https://staging.example.com" {
		t.Errorf("missing staging_url in config")
	}
	if _, ok := cfg["site_map_json"]; !ok {
		t.Error("expected site_map_json in prove config")
	}
}

func TestAdvanceStage_IdempotencyGuard(t *testing.T) {
	pipeline := &model.Pipeline{
		ID: "p-1", Stages: []string{"scan", "discover", "prove"},
		ScanAuditID: "a-scan",
		Status:      model.PipelineStatusDiscoverRunning, // already past scan
	}
	var auditCreated bool
	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(string) (*model.Pipeline, error) { return pipeline, nil },
		UpdatePipelineFn:       func(*model.Pipeline) error { return nil },
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(*model.AuditRequest) (*model.Audit, error) {
			auditCreated = true
			return &model.Audit{ID: "no"}, nil
		},
	}
	svc := NewPipelineService(repo, auditSvc, nil)

	err := svc.AdvanceStage("a-scan", model.AuditStatusCompleted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auditCreated {
		t.Error("audit should NOT be created on duplicate advance")
	}
}

// --- RED: Tests for CreatePipeline launching first stage ---

func TestCreatePipeline_StartsFirstStage(t *testing.T) {
	var createdReq *model.AuditRequest
	var updatedPipeline *model.Pipeline

	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(*model.Pipeline) error { return nil },
		UpdatePipelineFn: func(p *model.Pipeline) error {
			updatedPipeline = p
			return nil
		},
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			createdReq = req
			return &model.Audit{ID: "audit-scan-1"}, nil
		},
	}
	svc := NewPipelineService(repo, auditSvc, nil)

	pipeline, err := svc.CreatePipeline(&model.PipelineRequest{
		SourceID: "src-1", TargetURL: "https://staging.example.com",
		Stages: []string{"scan", "discover", "prove"},
	})
	if err != nil {
		t.Fatalf("CreatePipeline: %v", err)
	}
	if createdReq == nil {
		t.Fatal("expected first audit created")
	}
	if pipeline.ScanAuditID != "audit-scan-1" {
		t.Errorf("expected scan_audit_id set, got %q", pipeline.ScanAuditID)
	}
	if updatedPipeline == nil || updatedPipeline.Status != model.PipelineStatusScanRunning {
		t.Error("expected scan_running after create")
	}
}

// --- RED: Tests for scan findings injection into discover config ---

func TestGetStageAuditConfig_DiscoverWithScanFindings(t *testing.T) {
	pipeline := &model.Pipeline{
		TargetURL:   "https://staging.example.com",
		SourceID:    "src-1",
		ScanAuditID: "scan-a-1",
		Config:      json.RawMessage(`{}`),
	}
	auditSvc := &mockPipelineAuditSvc{
		getFn: func(id string) (*model.Audit, error) {
			if id == "scan-a-1" {
				return &model.Audit{
					ID: id,
					Findings: []model.Finding{
						{Title: "SQL Injection", FilePath: "/api/users.py", Category: "injection", Severity: "high"},
					},
				}, nil
			}
			return nil, nil
		},
	}
	svc := NewPipelineService(nil, auditSvc, nil)

	cfg, err := svc.GetStageAuditConfig(pipeline, "discover")
	if err != nil {
		t.Fatalf("GetStageAuditConfig: %v", err)
	}
	var m map[string]interface{}
	json.Unmarshal(cfg, &m)
	if m["target_url"] != "https://staging.example.com" {
		t.Errorf("missing target_url")
	}
	if _, ok := m["scan_findings"]; !ok {
		t.Error("expected scan_findings in discover config")
	}
}

// --- RED: Full pipeline lifecycle test ---

func TestPipelineFullLifecycle(t *testing.T) {
	audits := map[string]*model.Audit{}
	counter := 0

	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			counter++
			id := fmt.Sprintf("audit-%d", counter)
			a := &model.Audit{
				ID: id, SourceID: req.SourceID, Types: req.Types, Config: req.Config,
				Findings: []model.Finding{{Title: "F", FilePath: "/api/t.py", Category: "inj"}},
			}
			audits[id] = a
			return a, nil
		},
		getFn: func(id string) (*model.Audit, error) { return audits[id], nil },
	}
	discoverSvc := &mockPipelineDiscoverSvc{
		getResultFn: func(string) (*model.DiscoverResult, error) {
			return &model.DiscoverResult{SiteMapJSON: `{"urls":["/api"]}`}, nil
		},
	}

	pipelines := map[string]*model.Pipeline{}
	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(p *model.Pipeline) error { pipelines[p.ID] = p; return nil },
		UpdatePipelineFn: func(p *model.Pipeline) error { pipelines[p.ID] = p; return nil },
		GetPipelineByAuditIDFn: func(auditID string) (*model.Pipeline, error) {
			for _, p := range pipelines {
				if p.ScanAuditID == auditID || p.DiscoverAuditID == auditID || p.ProveAuditID == auditID {
					return p, nil
				}
			}
			return nil, nil
		},
	}

	svc := NewPipelineService(repo, auditSvc, discoverSvc)

	// 1. Create pipeline (prove auto-expands to [scan, discover, prove])
	pipeline, err := svc.CreatePipeline(&model.PipelineRequest{
		SourceID: "src-1", TargetURL: "https://staging.example.com",
		Stages: []string{"prove"}, Config: json.RawMessage(`{"types":["owasp"]}`),
	})
	if err != nil {
		t.Fatalf("CreatePipeline: %v", err)
	}
	if pipeline.Status != model.PipelineStatusScanRunning {
		t.Fatalf("expected scan_running, got %s", pipeline.Status)
	}

	// 2. Scan completes → discover triggers
	if err := svc.AdvanceStage(pipeline.ScanAuditID, model.AuditStatusCompleted); err != nil {
		t.Fatalf("AdvanceStage(scan): %v", err)
	}
	p := pipelines[pipeline.ID]
	if p.Status != model.PipelineStatusDiscoverRunning {
		t.Fatalf("expected discover_running, got %s", p.Status)
	}

	// 3. Discover completes → prove triggers
	if err := svc.AdvanceStage(p.DiscoverAuditID, model.AuditStatusCompleted); err != nil {
		t.Fatalf("AdvanceStage(discover): %v", err)
	}
	p = pipelines[pipeline.ID]
	if p.Status != model.PipelineStatusProveRunning {
		t.Fatalf("expected prove_running, got %s", p.Status)
	}

	// 4. Prove completes → pipeline completed
	if err := svc.AdvanceStage(p.ProveAuditID, model.AuditStatusCompleted); err != nil {
		t.Fatalf("AdvanceStage(prove): %v", err)
	}
	p = pipelines[pipeline.ID]
	if p.Status != model.PipelineStatusCompleted {
		t.Fatalf("expected completed, got %s", p.Status)
	}
	if counter != 3 {
		t.Errorf("expected 3 audits created, got %d", counter)
	}
}

// --- RED: Error path tests ---

func TestAdvanceStage_AuditCreateError(t *testing.T) {
	pipeline := &model.Pipeline{
		ID: "p-1", Stages: []string{"scan", "discover"},
		ScanAuditID: "a-scan", Config: json.RawMessage(`{}`),
		Status: model.PipelineStatusScanRunning,
	}
	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(string) (*model.Pipeline, error) { return pipeline, nil },
		UpdatePipelineFn:       func(*model.Pipeline) error { return nil },
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(*model.AuditRequest) (*model.Audit, error) {
			return nil, fmt.Errorf("audit service down")
		},
	}
	svc := NewPipelineService(repo, auditSvc, nil)

	err := svc.AdvanceStage("a-scan", model.AuditStatusCompleted)
	if err == nil {
		t.Fatal("expected error when audit creation fails")
	}
}

func TestCreatePipeline_EmptyStages(t *testing.T) {
	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(*model.Pipeline) error { return nil },
	}
	svc := NewPipelineService(repo, &mockPipelineAuditSvc{}, nil)

	pipeline, err := svc.CreatePipeline(&model.PipelineRequest{
		SourceID: "src-1", TargetURL: "https://example.com", Stages: []string{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pipeline.Status != model.PipelineStatusPending {
		t.Errorf("expected pending for empty stages, got %s", pipeline.Status)
	}
}
