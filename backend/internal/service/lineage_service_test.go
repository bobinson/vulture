package service

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

func TestProcessAuditFindings_NewFinding(t *testing.T) {
	var upserted *model.FindingLineage
	var addedEvent *model.LineageEvent
	mock := &repository.MockLineageRepository{
		GetLineageByFingerprintsFn: func(fps []string, sp string) (map[string]*model.FindingLineage, error) { return nil, nil },
		UpsertLineageFn:            func(l *model.FindingLineage) error { upserted = l; l.ID = "lineage-1"; return nil },
		AddEventFn:                 func(e *model.LineageEvent) error { addedEvent = e; return nil },
		GetOpenBySourcePathFn:      func(sp, at string) ([]model.FindingLineage, error) { return nil, nil },
	}
	svc := NewLineageService(mock)

	audit := &model.Audit{ID: "audit-1"}
	source := &model.Source{Path: "/path", GitCommitShort: "abc1234", GitBranch: "main"}
	findings := []model.Finding{
		{Fingerprint: "fp-1", AgentType: "chaos", Severity: "high", Category: "retry", Title: "No retry", FilePath: "main.go"},
	}

	err := svc.ProcessAuditFindings(audit, source, findings)
	if err != nil {
		t.Fatalf("ProcessAuditFindings: %v", err)
	}
	if upserted == nil {
		t.Fatal("expected upsert call for new finding")
	}
	if upserted.Fingerprint != "fp-1" {
		t.Errorf("expected fingerprint fp-1, got %s", upserted.Fingerprint)
	}
	if upserted.CurrentStatus != model.LineageStatusOpen {
		t.Errorf("expected status open, got %s", upserted.CurrentStatus)
	}
	if upserted.FirstCommit != "abc1234" {
		t.Errorf("expected first_commit abc1234, got %s", upserted.FirstCommit)
	}
	if upserted.LatestCommit != "abc1234" {
		t.Errorf("expected latest_commit abc1234, got %s", upserted.LatestCommit)
	}
	if addedEvent == nil || addedEvent.EventType != model.LineageEventDetected {
		t.Fatal("expected 'detected' event")
	}
	if addedEvent.GitCommit != "abc1234" {
		t.Errorf("expected event git_commit abc1234, got %s", addedEvent.GitCommit)
	}
	if addedEvent.GitBranch != "main" {
		t.Errorf("expected event git_branch main, got %s", addedEvent.GitBranch)
	}
}

func TestProcessAuditFindings_Regression(t *testing.T) {
	var regressionCalled bool
	var regressionEvent *model.LineageEvent
	existing := &model.FindingLineage{
		ID: "lineage-1", Fingerprint: "fp-1",
		CurrentStatus: model.LineageStatusFixed,
	}
	mock := &repository.MockLineageRepository{
		GetLineageByFingerprintsFn: func(fps []string, sp string) (map[string]*model.FindingLineage, error) {
			return map[string]*model.FindingLineage{"fp-1|chaos": existing}, nil
		},
		UpsertLineageFn:       func(l *model.FindingLineage) error { return nil },
		MarkRegressionFn:      func(id, aid, c string) error { regressionCalled = true; return nil },
		AddEventFn:            func(e *model.LineageEvent) error { regressionEvent = e; return nil },
		GetOpenBySourcePathFn: func(sp, at string) ([]model.FindingLineage, error) { return nil, nil },
	}
	svc := NewLineageService(mock)

	err := svc.ProcessAuditFindings(
		&model.Audit{ID: "audit-2"},
		&model.Source{Path: "/path"},
		[]model.Finding{{Fingerprint: "fp-1", AgentType: "chaos"}},
	)
	if err != nil {
		t.Fatalf("ProcessAuditFindings: %v", err)
	}
	if !regressionCalled {
		t.Error("expected MarkRegression to be called")
	}
	if regressionEvent == nil || regressionEvent.EventType != model.LineageEventRegression {
		t.Error("expected 'regression' event")
	}
}

func TestProcessAuditFindings_FixDetection(t *testing.T) {
	var fixedID string
	openLineages := []model.FindingLineage{
		{ID: "lineage-old", Fingerprint: "fp-old", CurrentStatus: model.LineageStatusOpen},
	}
	mock := &repository.MockLineageRepository{
		GetLineageByFingerprintsFn: func(fps []string, sp string) (map[string]*model.FindingLineage, error) { return nil, nil },
		UpsertLineageFn:            func(l *model.FindingLineage) error { l.ID = "lineage-new"; return nil },
		AddEventFn:                 func(e *model.LineageEvent) error { return nil },
		GetOpenBySourcePathFn: func(sp, at string) ([]model.FindingLineage, error) {
			return openLineages, nil
		},
		MarkFixedFn: func(id, aid, c string) error { fixedID = id; return nil },
	}
	svc := NewLineageService(mock)

	// New finding has different fingerprint, old one should be marked fixed
	err := svc.ProcessAuditFindings(
		&model.Audit{ID: "audit-3"},
		&model.Source{Path: "/path"},
		[]model.Finding{{Fingerprint: "fp-new", AgentType: "chaos", Severity: "low", Category: "cat", Title: "t", FilePath: "f.go"}},
	)
	if err != nil {
		t.Fatalf("ProcessAuditFindings: %v", err)
	}
	if fixedID != "lineage-old" {
		t.Errorf("expected old lineage to be marked fixed, got %q", fixedID)
	}
}

func TestProcessAuditFindings_AcceptedRiskNotAutoFixed(t *testing.T) {
	var fixedCalled bool
	openLineages := []model.FindingLineage{
		{ID: "lineage-risk", Fingerprint: "fp-risk", CurrentStatus: model.LineageStatusAcceptedRisk},
	}
	mock := &repository.MockLineageRepository{
		GetLineageByFingerprintsFn: func(fps []string, sp string) (map[string]*model.FindingLineage, error) { return nil, nil },
		UpsertLineageFn:            func(l *model.FindingLineage) error { l.ID = "lineage-x"; return nil },
		AddEventFn:                 func(e *model.LineageEvent) error { return nil },
		GetOpenBySourcePathFn: func(sp, at string) ([]model.FindingLineage, error) {
			return openLineages, nil
		},
		MarkFixedFn: func(id, aid, c string) error { fixedCalled = true; return nil },
	}
	svc := NewLineageService(mock)

	err := svc.ProcessAuditFindings(
		&model.Audit{ID: "audit-4"},
		&model.Source{Path: "/path"},
		[]model.Finding{{Fingerprint: "fp-new", AgentType: "chaos", Severity: "low", Category: "cat", Title: "t", FilePath: "f.go"}},
	)
	if err != nil {
		t.Fatalf("ProcessAuditFindings: %v", err)
	}
	if fixedCalled {
		t.Error("accepted_risk lineage should NOT be auto-fixed")
	}
}

func TestUpdateStatus(t *testing.T) {
	existing := &model.FindingLineage{
		ID: "lineage-1", CurrentStatus: model.LineageStatusOpen,
	}
	var statusUpdated string
	var events []*model.LineageEvent
	mock := &repository.MockLineageRepository{
		GetLineageFn: func(id string) (*model.FindingLineage, error) { return existing, nil },
		UpdateStatusFn: func(id, status, notes, url string) error {
			statusUpdated = status
			return nil
		},
		AddEventFn: func(e *model.LineageEvent) error { events = append(events, e); return nil },
	}
	svc := NewLineageService(mock)

	err := svc.UpdateStatus("lineage-1", &model.LineageStatusUpdate{
		Status:    "in_progress",
		Notes:     "working on it",
		TicketURL: "https://jira.example.com/123",
	})
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if statusUpdated != "in_progress" {
		t.Errorf("expected status in_progress, got %s", statusUpdated)
	}
	if len(events) < 1 {
		t.Fatal("expected at least 1 event")
	}
	if events[0].EventType != model.LineageEventStatusChange {
		t.Errorf("expected status_change event, got %s", events[0].EventType)
	}
}

func TestUpdateStatus_NotFound(t *testing.T) {
	mock := &repository.MockLineageRepository{
		GetLineageFn: func(id string) (*model.FindingLineage, error) { return nil, nil },
	}
	svc := NewLineageService(mock)

	err := svc.UpdateStatus("nonexistent", &model.LineageStatusUpdate{Status: "open"})
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestGetTimeline(t *testing.T) {
	events := []model.LineageEvent{
		{ID: "e-1", LineageID: "l-1", EventType: model.LineageEventDetected, CreatedAt: time.Now()},
	}
	mock := &repository.MockLineageRepository{
		GetEventsFn: func(id string) ([]model.LineageEvent, error) { return events, nil },
	}
	svc := NewLineageService(mock)

	result, err := svc.GetTimeline("l-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 event, got %d", len(result))
	}
}
