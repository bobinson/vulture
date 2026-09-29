package handler

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Equal (here zero) creation times resolve the requested audit as the newer
// one, so a mapping-mode current audit still drops the older copies and the
// input slices are left untouched.
func TestBuildComparisonDropsLegacyCopiesOnTiedTimes(t *testing.T) {
	previous := &model.Audit{ID: "prev", Types: []string{"cwe", "owasp"}, Findings: []model.Finding{
		{Fingerprint: "a", AgentType: "cwe", Severity: model.SeverityHigh},
		{Fingerprint: "a-copy", AgentType: "owasp", Severity: model.SeverityHigh},
	}}
	current := &model.Audit{ID: "curr", Types: []string{"owasp", "cwe"}, Findings: []model.Finding{
		{Fingerprint: "a", AgentType: "cwe", Severity: model.SeverityHigh},
	}}

	comp := buildComparison(current, previous)

	if comp.FixedCount != 0 || comp.NewCount != 0 || comp.PersistentCount != 1 {
		t.Errorf("fixed/new/persistent = %d/%d/%d, want 0/0/1", comp.FixedCount, comp.NewCount, comp.PersistentCount)
	}
	if comp.ExcludedLegacyCopies != 1 {
		t.Errorf("ExcludedLegacyCopies = %d, want 1", comp.ExcludedLegacyCopies)
	}
	// The counts are those of the rows that entered the diff (M7): the copy is
	// reported in ExcludedLegacyCopies, not in PreviousFindingsCount.
	if len(previous.Findings) != 2 || comp.PreviousFindingsCount != 1 {
		t.Errorf("previous audit mutated or miscounted: %d rows, count %d", len(previous.Findings), comp.PreviousFindingsCount)
	}
}

// M7: the counts reconcile with the classification after the legacy copies
// are excluded — previous = persistent + changed + fixed, current = persistent
// + changed + new — in both directions (the requested audit newer or older).
func TestBuildComparisonCountsReconcileAfterExclusion(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	legacy := &model.Audit{ID: "legacy", Types: []string{"cwe", "owasp"}, CreatedAt: t0, Findings: []model.Finding{
		{Fingerprint: "a", AgentType: "cwe", Severity: model.SeverityHigh},
		{Fingerprint: "a-copy", AgentType: "owasp", Severity: model.SeverityHigh},
		{Fingerprint: "b-copy", AgentType: "owasp", Severity: model.SeverityHigh},
		{Fingerprint: "b", AgentType: "cwe", Severity: model.SeverityHigh},
		{Fingerprint: "d", AgentType: "cwe", Severity: model.SeverityHigh},
	}}
	mapping := &model.Audit{ID: "mapping", Types: []string{"cwe", "owasp"}, CreatedAt: t0.Add(time.Hour),
		Findings: []model.Finding{
			{Fingerprint: "a", AgentType: "cwe", Severity: model.SeverityHigh},
			{Fingerprint: "d", AgentType: "cwe", Severity: model.SeverityLow},
			{Fingerprint: "c", AgentType: "cwe", Severity: model.SeverityHigh},
		}}
	for name, pair := range map[string][2]*model.Audit{
		"requested audit is the newer": {mapping, legacy},
		"requested audit is the older": {legacy, mapping},
	} {
		comp := buildComparison(pair[0], pair[1])
		if comp.ExcludedLegacyCopies != 2 {
			t.Errorf("%s: excluded = %d, want 2", name, comp.ExcludedLegacyCopies)
		}
		if got := comp.PersistentCount + comp.ChangedCount + comp.FixedCount; comp.PreviousFindingsCount != got {
			t.Errorf("%s: previous_findings_count = %d, persistent+changed+fixed = %d",
				name, comp.PreviousFindingsCount, got)
		}
		if got := comp.PersistentCount + comp.ChangedCount + comp.NewCount; comp.CurrentFindingsCount != got {
			t.Errorf("%s: current_findings_count = %d, persistent+changed+new = %d",
				name, comp.CurrentFindingsCount, got)
		}
	}
}

// A current audit whose types exclude every mapper is never in mapping mode.
func TestBuildComparisonKeepsRowsWithoutMapperType(t *testing.T) {
	previous := &model.Audit{ID: "prev", Types: []string{"cwe"}, Findings: []model.Finding{
		{Fingerprint: "b", AgentType: "cwe", Severity: model.SeverityHigh},
	}}
	current := &model.Audit{ID: "curr", Types: []string{"cwe"}}

	comp := buildComparison(current, previous)

	if comp.FixedCount != 1 || comp.ExcludedLegacyCopies != 0 {
		t.Errorf("fixed = %d excluded = %d, want 1 and 0", comp.FixedCount, comp.ExcludedLegacyCopies)
	}
}
