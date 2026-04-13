package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/service"
)

// --- Mock for PipelineService ---

type mockPipelineSvc struct {
	advanceStageFn func(string, model.AuditStatus) error
}

func (m *mockPipelineSvc) CreatePipeline(*model.PipelineRequest) (*model.Pipeline, error)         { return nil, nil }
func (m *mockPipelineSvc) GetPipeline(string) (*model.Pipeline, error)                             { return nil, nil }
func (m *mockPipelineSvc) ListPipelines(int, int) ([]model.Pipeline, error)                        { return nil, nil }
func (m *mockPipelineSvc) GetStageAuditConfig(*model.Pipeline, string) (json.RawMessage, error)    { return nil, nil }
func (m *mockPipelineSvc) SetRunner(service.PipelineRunner)                                        {}
func (m *mockPipelineSvc) AdvanceStage(auditID string, status model.AuditStatus) error {
	if m.advanceStageFn != nil {
		return m.advanceStageFn(auditID, status)
	}
	return nil
}

// --- RED: persistResults calls AdvanceStage ---

func TestPersistResults_CallsAdvanceStage(t *testing.T) {
	var advancedID string
	var advancedStatus model.AuditStatus

	pSvc := &mockPipelineSvc{
		advanceStageFn: func(id string, s model.AuditStatus) error {
			advancedID = id
			advancedStatus = s
			return nil
		},
	}

	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, nil)
	h.SetPipelineService(pSvc)

	audit := &model.Audit{ID: "a-1", Types: []string{"owasp"}, Scores: map[string]int{}}
	h.persistResults(audit, nil, []model.Finding{{Title: "Bug", AgentType: "owasp"}}, map[string]int{"owasp": 80}, nil)

	if advancedID != "a-1" {
		t.Errorf("expected AdvanceStage with a-1, got %q", advancedID)
	}
	if advancedStatus != model.AuditStatusCompleted {
		t.Errorf("expected completed, got %s", advancedStatus)
	}
}

// --- RED: RunPipelineStage executes and persists ---

func TestRunPipelineStage_ExecutesAndPersists(t *testing.T) {
	var updatedAudit *model.Audit
	auditSvc := &mockAuditService{
		getFn: func(id string) (*model.Audit, error) {
			return &model.Audit{
				ID: id, SourceID: "s-1", Types: []string{"owasp"},
				Status: model.AuditStatusPending, Scores: map[string]int{},
			}, nil
		},
		updateFn: func(a *model.Audit) error { updatedAudit = a; return nil },
	}
	sourceSvc := &mockSourceService{
		getFn: func(string) (*model.Source, error) {
			return &model.Source{ID: "s-1", Path: "/test"}, nil
		},
	}
	streamSvc := &mockStreamService{
		streamWithContextFn: func(_ context.Context, _ *model.Audit, _ string, _ map[string]config.AgentConfig, _ map[string][]model.PriorFinding, eventCh chan<- *model.AgUIEvent) {
			eventCh <- &model.AgUIEvent{Type: model.EventRunStarted, RunID: "a-1"}
			close(eventCh)
		},
	}

	h := NewStreamHandler(auditSvc, sourceSvc, streamSvc, map[string]config.AgentConfig{
		"owasp": {URL: "http://agent-owasp:28002"},
	})

	h.runPipelineAudit("a-1")

	if updatedAudit == nil {
		t.Fatal("expected audit updated")
	}
	if updatedAudit.Status != model.AuditStatusCompleted {
		t.Errorf("expected completed, got %s", updatedAudit.Status)
	}
}

// --- RED: consumeEventsNoSSE ---

func TestConsumeEventsNoSSE(t *testing.T) {
	eventCh := make(chan *model.AgUIEvent, 2)
	snapshot, _ := json.Marshal(map[string]interface{}{
		"findings": []model.Finding{{Title: "Bug", Severity: "high"}},
		"score":    80.0,
	})
	eventCh <- &model.AgUIEvent{
		Type: model.EventStateSnapshot, Snapshot: snapshot, AgentType: "owasp",
	}
	close(eventCh)

	findings, scores, _ := consumeEventsNoSSE(eventCh, "a-1")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if scores["owasp"] != 80 {
		t.Errorf("expected score 80, got %d", scores["owasp"])
	}
}

// --- RED: AdvanceStage error is logged, not fatal ---

func TestPersistResults_AdvanceStageErrorNonFatal(t *testing.T) {
	pSvc := &mockPipelineSvc{
		advanceStageFn: func(string, model.AuditStatus) error {
			return json.Unmarshal([]byte("bad"), nil) // some error
		},
	}
	h := NewStreamHandler(&mockAuditService{}, &mockSourceService{}, &mockStreamService{}, nil)
	h.SetPipelineService(pSvc)

	audit := &model.Audit{ID: "a-1", Types: []string{"owasp"}, Scores: map[string]int{}}
	// Should not panic
	h.persistResults(audit, nil, []model.Finding{{Title: "Bug"}}, map[string]int{}, nil)
}
