package service

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// TestPipelineService_DefaultScanTypesInjected proves the scan stage
// uses the provider injected at construction time, not the legacy
// config.ScanAgentTypes() fallback. Feature 0049 follow-up.
func TestPipelineService_DefaultScanTypesInjected(t *testing.T) {
	var seenTypes []string
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			seenTypes = append([]string(nil), req.Types...)
			return &model.Audit{ID: "audit-1"}, nil
		},
	}
	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(p *model.Pipeline) error { return nil },
		UpdatePipelineFn: func(p *model.Pipeline) error { return nil },
	}

	provider := func() []string { return []string{"chaos", "owasp", "semgrep-external"} }
	svc := NewPipelineServiceWithScanTypes(repo, auditSvc, nil, provider)

	req := &model.PipelineRequest{
		SourceID: "src-1",
		Stages:   []string{"scan"},
		Config:   json.RawMessage(`{}`),
	}
	if _, err := svc.CreatePipeline(req); err != nil {
		t.Fatalf("CreatePipeline: %v", err)
	}
	sort.Strings(seenTypes)
	want := []string{"chaos", "owasp", "semgrep-external"}
	if len(seenTypes) != len(want) {
		t.Fatalf("expected %v, got %v", want, seenTypes)
	}
	for i := range want {
		if seenTypes[i] != want[i] {
			t.Errorf("want[%d]=%q, got %q", i, want[i], seenTypes[i])
		}
	}
}

// TestPipelineService_ExplicitTypesOverrideProvider documents that an
// explicit `types` array in the pipeline config wins over the
// injected default-scan-types provider. The provider is the
// fallback, not the authoritative source.
func TestPipelineService_ExplicitTypesOverrideProvider(t *testing.T) {
	var seenTypes []string
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			seenTypes = append([]string(nil), req.Types...)
			return &model.Audit{ID: "audit-2"}, nil
		},
	}
	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(p *model.Pipeline) error { return nil },
		UpdatePipelineFn: func(p *model.Pipeline) error { return nil },
	}
	provider := func() []string { return []string{"should", "not", "appear"} }
	svc := NewPipelineServiceWithScanTypes(repo, auditSvc, nil, provider)

	req := &model.PipelineRequest{
		SourceID: "src-2",
		Stages:   []string{"scan"},
		Config:   json.RawMessage(`{"types":["owasp"]}`),
	}
	if _, err := svc.CreatePipeline(req); err != nil {
		t.Fatalf("CreatePipeline: %v", err)
	}
	if len(seenTypes) != 1 || seenTypes[0] != "owasp" {
		t.Errorf("explicit types should win; got %v", seenTypes)
	}
}

// TestPipelineService_NilProviderFallsBackToConfig confirms that
// passing a nil provider to NewPipelineServiceWithScanTypes is safe
// and uses the legacy config.ScanAgentTypes() path.
func TestPipelineService_NilProviderFallsBackToConfig(t *testing.T) {
	var seenTypes []string
	auditSvc := &mockPipelineAuditSvc{
		createFn: func(req *model.AuditRequest) (*model.Audit, error) {
			seenTypes = append([]string(nil), req.Types...)
			return &model.Audit{ID: "audit-3"}, nil
		},
	}
	repo := &repository.MockPipelineRepo{
		CreatePipelineFn: func(p *model.Pipeline) error { return nil },
		UpdatePipelineFn: func(p *model.Pipeline) error { return nil },
	}
	svc := NewPipelineServiceWithScanTypes(repo, auditSvc, nil, nil)
	req := &model.PipelineRequest{
		SourceID: "src-3",
		Stages:   []string{"scan"},
		Config:   json.RawMessage(`{}`),
	}
	if _, err := svc.CreatePipeline(req); err != nil {
		t.Fatalf("CreatePipeline: %v", err)
	}
	// Should be the in-tree default scan set — non-empty, includes
	// "owasp" and "chaos" but not "prove"/"discover".
	if len(seenTypes) == 0 {
		t.Fatal("expected non-empty default scan set")
	}
	for _, banned := range []string{"prove", "discover"} {
		for _, got := range seenTypes {
			if got == banned {
				t.Errorf("default scan set must not contain pipeline stage %q (got %v)", banned, seenTypes)
			}
		}
	}
}
