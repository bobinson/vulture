package service

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

func TestExpandStages_ProveAutoExpands(t *testing.T) {
	stages := expandStages([]string{"prove"}, true)
	expected := []string{"scan", "discover", "prove"}
	if len(stages) != 3 {
		t.Fatalf("expected 3 stages, got %d: %v", len(stages), stages)
	}
	for i, s := range expected {
		if stages[i] != s {
			t.Errorf("stage[%d] = %s, want %s", i, stages[i], s)
		}
	}
}

func TestExpandStages_DiscoverWithSource(t *testing.T) {
	stages := expandStages([]string{"discover"}, true)
	expected := []string{"scan", "discover"}
	if len(stages) != 2 {
		t.Fatalf("expected 2 stages, got %d: %v", len(stages), stages)
	}
	for i, s := range expected {
		if stages[i] != s {
			t.Errorf("stage[%d] = %s, want %s", i, stages[i], s)
		}
	}
}

func TestExpandStages_DiscoverWithoutSource(t *testing.T) {
	stages := expandStages([]string{"discover"}, false)
	if len(stages) != 1 || stages[0] != "discover" {
		t.Errorf("expected [discover], got %v", stages)
	}
}

func TestExpandStages_ScanOnly(t *testing.T) {
	stages := expandStages([]string{"scan"}, true)
	if len(stages) != 1 || stages[0] != "scan" {
		t.Errorf("expected [scan], got %v", stages)
	}
}

func TestExpandStages_ScanAndDiscover(t *testing.T) {
	stages := expandStages([]string{"scan", "discover"}, true)
	expected := []string{"scan", "discover"}
	if len(stages) != 2 {
		t.Fatalf("expected 2 stages, got %d: %v", len(stages), stages)
	}
	for i, s := range expected {
		if stages[i] != s {
			t.Errorf("stage[%d] = %s, want %s", i, stages[i], s)
		}
	}
}

func TestPipelineService_CreatePipeline(t *testing.T) {
	var created *model.Pipeline
	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(p *model.Pipeline) error {
			created = p
			return nil
		},
		UpdatePipelineFn: func(p *model.Pipeline) error { return nil },
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			return &model.Audit{ID: "a-first"}, nil
		},
	}
	svc := NewPipelineService(repo, auditSvc, nil)

	req := &model.PipelineRequest{
		SourceID:  "src-1",
		TargetURL: "https://staging.example.com",
		Stages:    []string{"prove"},
	}
	pipeline, err := svc.CreatePipeline(req)
	if err != nil {
		t.Fatalf("CreatePipeline: %v", err)
	}
	// CreatePipeline now launches first stage, so status should be scan_running
	if pipeline.Status != model.PipelineStatusScanRunning {
		t.Errorf("expected scan_running, got %s", pipeline.Status)
	}
	if len(created.Stages) != 3 {
		t.Errorf("expected 3 stages, got %d: %v", len(created.Stages), created.Stages)
	}
}

func TestPipelineService_AdvanceStage_Completes(t *testing.T) {
	pipeline := &model.Pipeline{
		ID:              "p-1",
		Stages:          []string{"scan"},
		ScanAuditID:     "audit-1",
		Status:          model.PipelineStatusScanRunning,
	}
	var updated *model.Pipeline
	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(auditID string) (*model.Pipeline, error) {
			if auditID == "audit-1" {
				return pipeline, nil
			}
			return nil, nil
		},
		UpdatePipelineFn: func(p *model.Pipeline) error {
			updated = p
			return nil
		},
	}
	svc := NewPipelineService(repo, nil, nil)

	err := svc.AdvanceStage("audit-1", model.AuditStatusCompleted)
	if err != nil {
		t.Fatalf("AdvanceStage: %v", err)
	}
	if updated.Status != model.PipelineStatusCompleted {
		t.Errorf("expected completed, got %s", updated.Status)
	}
}

func TestPipelineService_AdvanceStage_FailsPipeline(t *testing.T) {
	pipeline := &model.Pipeline{
		ID:          "p-1",
		Stages:      []string{"scan", "discover"},
		ScanAuditID: "audit-1",
		Status:      model.PipelineStatusScanRunning,
	}
	var updated *model.Pipeline
	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(auditID string) (*model.Pipeline, error) {
			return pipeline, nil
		},
		UpdatePipelineFn: func(p *model.Pipeline) error {
			updated = p
			return nil
		},
	}
	svc := NewPipelineService(repo, nil, nil)

	err := svc.AdvanceStage("audit-1", model.AuditStatusFailed)
	if err != nil {
		t.Fatalf("AdvanceStage: %v", err)
	}
	if updated.Status != model.PipelineStatusFailed {
		t.Errorf("expected failed, got %s", updated.Status)
	}
}

func TestPipelineService_AdvanceStage_NextStage(t *testing.T) {
	pipeline := &model.Pipeline{
		ID:          "p-1",
		Stages:      []string{"scan", "discover", "prove"},
		ScanAuditID: "audit-1",
		Config:      json.RawMessage(`{}`),
		Status:      model.PipelineStatusScanRunning,
	}
	var updated *model.Pipeline
	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(auditID string) (*model.Pipeline, error) {
			return pipeline, nil
		},
		UpdatePipelineFn: func(p *model.Pipeline) error {
			updated = p
			return nil
		},
	}
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			return &model.Audit{ID: "a-discover"}, nil
		},
	}
	svc := NewPipelineService(repo, auditSvc, nil)

	err := svc.AdvanceStage("audit-1", model.AuditStatusCompleted)
	if err != nil {
		t.Fatalf("AdvanceStage: %v", err)
	}
	if updated.Status != model.PipelineStatusDiscoverRunning {
		t.Errorf("expected discover_running, got %s", updated.Status)
	}
}

func TestPipelineService_AdvanceStage_NoopForNonPipeline(t *testing.T) {
	repo := &repository.MockPipelineRepo{
		GetPipelineByAuditIDFn: func(auditID string) (*model.Pipeline, error) {
			return nil, nil
		},
	}
	svc := NewPipelineService(repo, nil, nil)

	err := svc.AdvanceStage("audit-xyz", model.AuditStatusCompleted)
	if err != nil {
		t.Fatalf("AdvanceStage: %v", err)
	}
}

func TestPipelineService_GetStageAuditConfig_Discover(t *testing.T) {
	pipeline := &model.Pipeline{
		TargetURL: "https://staging.example.com",
		Config:    json.RawMessage(`{"types":["owasp"]}`),
	}
	svc := NewPipelineService(nil, nil, nil)

	cfg, err := svc.GetStageAuditConfig(pipeline, "discover")
	if err != nil {
		t.Fatalf("GetStageAuditConfig: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["target_url"] != "https://staging.example.com" {
		t.Errorf("expected target_url, got %v", m)
	}
}

func TestPipelineService_GetStageAuditConfig_ProveWithDiscoverResult(t *testing.T) {
	pipeline := &model.Pipeline{
		TargetURL:       "https://staging.example.com",
		DiscoverAuditID: "discover-audit-1",
		Config:          json.RawMessage(`{}`),
	}
	discoverSvc := NewDiscoverService(&repository.MockDiscoverRepo{
		GetDiscoverResultByAuditIDFn: func(auditID string) (*model.DiscoverResult, error) {
			return &model.DiscoverResult{
				SiteMapJSON: `{"urls":["/api/users"]}`,
			}, nil
		},
	})
	svc := NewPipelineService(nil, nil, discoverSvc)

	cfg, err := svc.GetStageAuditConfig(pipeline, "prove")
	if err != nil {
		t.Fatalf("GetStageAuditConfig: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["staging_url"] != "https://staging.example.com" {
		t.Errorf("expected staging_url, got %v", m)
	}
	if _, ok := m["site_map_json"]; !ok {
		t.Error("expected site_map_json to be injected")
	}
}

func TestStageToRunning(t *testing.T) {
	tests := []struct {
		stage string
		want  model.PipelineStatus
	}{
		{"scan", model.PipelineStatusScanRunning},
		{"discover", model.PipelineStatusDiscoverRunning},
		{"prove", model.PipelineStatusProveRunning},
		{"unknown", model.PipelineStatusPending},
	}
	for _, tt := range tests {
		got := stageToRunning(tt.stage)
		if got != tt.want {
			t.Errorf("stageToRunning(%q) = %s, want %s", tt.stage, got, tt.want)
		}
	}
}
