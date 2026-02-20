package service

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

func TestAuditService_Create_Success(t *testing.T) {
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return &model.Source{ID: id, Path: "/src"}, nil
		},
		CreateAuditFn: func(a *model.Audit) error {
			return nil
		},
	}
	svc := NewAuditService(repo)

	req := &model.AuditRequest{
		SourceID: "src-1",
		Types:    []string{"owasp"},
		Config:   json.RawMessage(`{"owasp":{}}`),
	}
	audit, err := svc.Create(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if audit.SourceID != "src-1" {
		t.Errorf("got source_id=%q, want %q", audit.SourceID, "src-1")
	}
	if audit.Status != model.AuditStatusPending {
		t.Errorf("got status=%q, want %q", audit.Status, model.AuditStatusPending)
	}
	if len(audit.Types) != 1 || audit.Types[0] != "owasp" {
		t.Errorf("got types=%v, want [owasp]", audit.Types)
	}
}

func TestAuditService_Create_NilConfig(t *testing.T) {
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return &model.Source{ID: id}, nil
		},
		CreateAuditFn: func(a *model.Audit) error {
			if string(a.Config) != "{}" {
				t.Errorf("expected default config={}, got %s", string(a.Config))
			}
			return nil
		},
	}
	svc := NewAuditService(repo)

	req := &model.AuditRequest{SourceID: "src-1", Types: []string{"chaos"}}
	audit, err := svc.Create(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(audit.Config) != "{}" {
		t.Errorf("expected default config, got %s", string(audit.Config))
	}
}

func TestAuditService_Create_SourceNotFound(t *testing.T) {
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return nil, nil // not found
		},
	}
	svc := NewAuditService(repo)

	_, err := svc.Create(&model.AuditRequest{SourceID: "missing"})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAuditService_Create_RepoGetError(t *testing.T) {
	repoErr := errors.New("db connection lost")
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return nil, repoErr
		},
	}
	svc := NewAuditService(repo)

	_, err := svc.Create(&model.AuditRequest{SourceID: "src-1"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped db error, got %v", err)
	}
}

func TestAuditService_Create_RepoCreateError(t *testing.T) {
	repoErr := errors.New("insert failed")
	repo := &repository.MockAuditRepository{
		GetSourceFn: func(id string) (*model.Source, error) {
			return &model.Source{ID: id}, nil
		},
		CreateAuditFn: func(a *model.Audit) error {
			return repoErr
		},
	}
	svc := NewAuditService(repo)

	_, err := svc.Create(&model.AuditRequest{SourceID: "src-1", Types: []string{"owasp"}})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped insert error, got %v", err)
	}
}

func TestAuditService_Get_Success(t *testing.T) {
	expected := &model.Audit{ID: "a-1", Status: model.AuditStatusCompleted}
	repo := &repository.MockAuditRepository{
		GetAuditFn: func(id string) (*model.Audit, error) {
			if id != "a-1" {
				t.Errorf("unexpected id: %s", id)
			}
			return expected, nil
		},
	}
	svc := NewAuditService(repo)

	audit, err := svc.Get("a-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if audit.ID != "a-1" {
		t.Errorf("got id=%q, want a-1", audit.ID)
	}
}

func TestAuditService_Get_NotFound(t *testing.T) {
	repo := &repository.MockAuditRepository{
		GetAuditFn: func(id string) (*model.Audit, error) {
			return nil, nil
		},
	}
	svc := NewAuditService(repo)

	_, err := svc.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAuditService_Get_RepoError(t *testing.T) {
	repoErr := errors.New("db read failed")
	repo := &repository.MockAuditRepository{
		GetAuditFn: func(id string) (*model.Audit, error) {
			return nil, repoErr
		},
	}
	svc := NewAuditService(repo)

	_, err := svc.Get("a-1")
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped repo error, got %v", err)
	}
}

func TestAuditService_Update(t *testing.T) {
	called := false
	repo := &repository.MockAuditRepository{
		UpdateAuditFn: func(a *model.Audit) error {
			called = true
			if a.ID != "a-1" {
				t.Errorf("unexpected audit id: %s", a.ID)
			}
			return nil
		},
	}
	svc := NewAuditService(repo)

	err := svc.Update(&model.Audit{ID: "a-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("repo.UpdateAudit was not called")
	}
}

func TestAuditService_SaveFindings(t *testing.T) {
	var gotID string
	var gotFindings []model.Finding
	repo := &repository.MockAuditRepository{
		SaveFindingsFn: func(id string, f []model.Finding) error {
			gotID = id
			gotFindings = f
			return nil
		},
	}
	svc := NewAuditService(repo)

	findings := []model.Finding{{ID: "f-1", Title: "XSS"}}
	err := svc.SaveFindings("a-1", findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != "a-1" {
		t.Errorf("got auditID=%q, want a-1", gotID)
	}
	if len(gotFindings) != 1 {
		t.Errorf("got %d findings, want 1", len(gotFindings))
	}
}

func TestAuditService_List(t *testing.T) {
	var gotLimit, gotOffset int
	repo := &repository.MockAuditRepository{
		ListAuditsFn: func(limit, offset int) ([]model.Audit, error) {
			gotLimit = limit
			gotOffset = offset
			return []model.Audit{{ID: "a-1"}, {ID: "a-2"}}, nil
		},
	}
	svc := NewAuditService(repo)

	audits, err := svc.List(10, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLimit != 10 || gotOffset != 5 {
		t.Errorf("got limit=%d offset=%d, want 10, 5", gotLimit, gotOffset)
	}
	if len(audits) != 2 {
		t.Errorf("got %d audits, want 2", len(audits))
	}
}

func TestAuditService_Stats(t *testing.T) {
	expected := &model.DashboardStats{AuditsRun: 5, TotalFindings: 42}
	repo := &repository.MockAuditRepository{
		GetStatsFn: func() (*model.DashboardStats, error) {
			return expected, nil
		},
	}
	svc := NewAuditService(repo)

	stats, err := svc.Stats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.AuditsRun != 5 || stats.TotalFindings != 42 {
		t.Errorf("unexpected stats: %+v", stats)
	}
}

func TestAuditService_GetCachedAudit(t *testing.T) {
	var gotSourceID string
	var gotTypes []string
	expected := &model.Audit{ID: "cached-1"}
	repo := &repository.MockAuditRepository{
		GetLatestCompletedAuditFn: func(srcID string, types []string) (*model.Audit, error) {
			gotSourceID = srcID
			gotTypes = types
			return expected, nil
		},
	}
	svc := NewAuditService(repo)

	audit, err := svc.GetCachedAudit("src-1", []string{"owasp", "soc2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if audit.ID != "cached-1" {
		t.Errorf("got id=%q, want cached-1", audit.ID)
	}
	if gotSourceID != "src-1" {
		t.Errorf("got sourceID=%q, want src-1", gotSourceID)
	}
	if len(gotTypes) != 2 {
		t.Errorf("got %d types, want 2", len(gotTypes))
	}
}

func TestAuditService_FindSourceByPath(t *testing.T) {
	expected := &model.Source{ID: "s-1", Path: "/my/project"}
	repo := &repository.MockAuditRepository{
		FindSourceByPathFn: func(path string) (*model.Source, error) {
			if path != "/my/project" {
				t.Errorf("unexpected path: %s", path)
			}
			return expected, nil
		},
	}
	svc := NewAuditService(repo)

	src, err := svc.FindSourceByPath("/my/project")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.ID != "s-1" {
		t.Errorf("got id=%q, want s-1", src.ID)
	}
}
