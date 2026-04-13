package service

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

func TestDiscoverService_SaveResult(t *testing.T) {
	var saved *model.DiscoverResult
	repo := &repository.MockDiscoverRepo{
		SaveDiscoverResultFn: func(dr *model.DiscoverResult) error {
			saved = dr
			return nil
		},
	}
	svc := NewDiscoverService(repo)

	dr := &model.DiscoverResult{
		ID:        "dr-1",
		AuditID:   "audit-1",
		TargetURL: "https://example.com",
		URLCount:  10,
		APICount:  5,
		CreatedAt: time.Now().UTC(),
	}
	err := svc.SaveResult(dr)
	if err != nil {
		t.Fatalf("SaveResult: %v", err)
	}
	if saved.ID != "dr-1" {
		t.Errorf("expected saved ID dr-1, got %s", saved.ID)
	}
}

func TestDiscoverService_SaveResult_RequiresAuditID(t *testing.T) {
	repo := &repository.MockDiscoverRepo{}
	svc := NewDiscoverService(repo)

	dr := &model.DiscoverResult{ID: "dr-1"}
	err := svc.SaveResult(dr)
	if err == nil {
		t.Error("expected error for missing audit_id")
	}
}

func TestDiscoverService_GetResultByAuditID(t *testing.T) {
	expected := &model.DiscoverResult{ID: "dr-1", AuditID: "audit-1"}
	repo := &repository.MockDiscoverRepo{
		GetDiscoverResultByAuditIDFn: func(auditID string) (*model.DiscoverResult, error) {
			if auditID == "audit-1" {
				return expected, nil
			}
			return nil, nil
		},
	}
	svc := NewDiscoverService(repo)

	dr, err := svc.GetResultByAuditID("audit-1")
	if err != nil {
		t.Fatalf("GetResultByAuditID: %v", err)
	}
	if dr.ID != "dr-1" {
		t.Errorf("expected ID dr-1, got %s", dr.ID)
	}
}

func TestDiscoverService_GetResultByTarget(t *testing.T) {
	expected := &model.DiscoverResult{ID: "dr-1", TargetURL: "https://example.com"}
	repo := &repository.MockDiscoverRepo{
		GetDiscoverResultByTargetFn: func(url string) (*model.DiscoverResult, error) {
			if url == "https://example.com" {
				return expected, nil
			}
			return nil, nil
		},
	}
	svc := NewDiscoverService(repo)

	dr, err := svc.GetResultByTarget("https://example.com")
	if err != nil {
		t.Fatalf("GetResultByTarget: %v", err)
	}
	if dr.ID != "dr-1" {
		t.Errorf("expected ID dr-1, got %s", dr.ID)
	}
}
