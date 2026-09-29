package service

import (
	"reflect"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §4.2 at the service seam: a sighting under a run's mapping
// hands the repo the FULL-table patch for that mapping's edition — on a new
// row and on a re-sighted one alike — and a sighting without a mapping hands
// it none. The merge itself (replace this key, keep the others) is the repo's
// and is pinned by the storage tests.
func TestRecordScanOutcomeCarriesTheMappingPatch(t *testing.T) {
	m := &model.ComplianceMapping{Framework: "owasp", Edition: "2025", Selected: []string{"A07"},
		Table: map[string][]model.ComplianceCategory{
			"CWE-798": {{ID: "A07", Name: "Auth"}},
			"CWE-259": {{ID: "A07", Name: "Auth"}, {ID: "A04", Name: "Crypto"}},
		}}
	existing := &model.FindingLineage{ID: "row-259", Fingerprint: "fp-259", AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen,
		// Read at the start of the scan; must never be replayed as the patch.
		ComplianceLabels: map[string][]string{"owasp:2021": {"A02"}}}
	byExisting := map[string]*model.FindingLineage{"fp-259|cwe": existing}
	patches := map[string]map[string][]string{}
	mock := &repository.MockLineageRepository{
		GetLineageByFingerprintsFn: func([]string, string) (map[string]*model.FindingLineage, error) { return byExisting, nil },
		GetLineageByFingerprintsForTargetFn: func([]string, string) (map[string]*model.FindingLineage, error) {
			return byExisting, nil
		},
		UpsertLineageFn: func(l *model.FindingLineage) error {
			patches[l.Fingerprint] = l.ComplianceLabels
			return nil
		},
	}
	findings := []model.Finding{
		{Fingerprint: "fp-798", AgentType: "cwe", Category: "CWE-798"},
		{Fingerprint: "fp-259", AgentType: "cwe", Category: "CWE-259"},
		{Fingerprint: "fp-1234", AgentType: "cwe", Category: "CWE-1234"},
		{Fingerprint: "fp-retry", AgentType: "cwe", Category: "retry"},
	}
	svc := NewLineageService(mock)
	source := &model.Source{Path: "/p"}
	if err := svc.RecordScanOutcome(&model.Audit{ID: "a-1"}, source, "cwe",
		&model.ScanResult{Findings: findings, ComplianceMapping: m}); err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string][]string{
		"fp-798": {"owasp:2025": {"A07"}},
		// The FULL table, although the audit selected A07 only.
		"fp-259": {"owasp:2025": {"A07", "A04"}},
		// Mapped to nothing by this edition: an explicit empty entry.
		"fp-1234":  {"owasp:2025": {}},
		"fp-retry": nil,
	}
	if !reflect.DeepEqual(patches, want) {
		t.Fatalf("patches = %v, want %v", patches, want)
	}

	patches = map[string]map[string][]string{}
	if err := svc.RecordScanOutcome(&model.Audit{ID: "a-2"}, source, "cwe",
		&model.ScanResult{Findings: findings}); err != nil {
		t.Fatal(err)
	}
	for fp, p := range patches {
		if p != nil {
			t.Errorf("a sighting without a mapping must send no labels: %s got %v", fp, p)
		}
	}
}
