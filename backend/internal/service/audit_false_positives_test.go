package service

import (
	"errors"
	"reflect"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// AuditFalsePositives reads the audit's lineage rows ONCE and resolves each
// finding to its own row (0096 follow-up: coverage excludes triaged false
// positives).
func TestAuditFalsePositives(t *testing.T) {
	var asked []string
	repo := &repository.MockLineageRepository{ListByAuditFn: func(id string) ([]model.FindingLineage, error) {
		asked = append(asked, id)
		return []model.FindingLineage{
			{ID: "row-v2", AgentType: "cwe", Fingerprint: "fp-original", FingerprintV2: "v2-b",
				CurrentStatus: model.LineageStatusFalsePositive},
			{ID: "row-a", AgentType: "cwe", Fingerprint: "fp-a", CurrentStatus: model.LineageStatusAcceptedRisk},
		}, nil
	}}
	findings := []model.Finding{
		{AgentType: "cwe", Fingerprint: "fp-a"},
		{AgentType: "cwe", Fingerprint: "fp-b", FingerprintV2: "v2-b"},
		{AgentType: "cwe", Fingerprint: "fp-c"},
	}
	got, err := AuditFalsePositives(repo, "audit-1", findings)
	if err != nil {
		t.Fatalf("AuditFalsePositives: %v", err)
	}
	if want := []bool{false, true, false}; !reflect.DeepEqual(got, want) {
		t.Errorf("triaged = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(asked, []string{"audit-1"}) {
		t.Errorf("lineage reads = %v, want exactly one for audit-1", asked)
	}
}

func TestAuditFalsePositivesPropagatesTheReadError(t *testing.T) {
	repo := &repository.MockLineageRepository{ListByAuditFn: func(string) ([]model.FindingLineage, error) {
		return nil, errors.New("boom")
	}}
	got, err := AuditFalsePositives(repo, "audit-1", []model.Finding{{AgentType: "cwe", Fingerprint: "fp"}})
	if err == nil || got != nil {
		t.Fatalf("got (%v, %v), want a nil mask and the error", got, err)
	}
}
