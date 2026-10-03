//go:build e2e

package e2e

import (
	"reflect"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 I1 with a VALID mapping. Every other valid-mapping fixture
// carries zero findings, so "zero OWASP rows" could not fail there: a backend
// that dropped copy rows only when the mapping was REJECTED would pass them
// all. Here the mapping is valid and the result still carries copies — one on
// its own file, re-sighting an OWASP lineage row if it reached the closure
// pass, and one at the CWE row's own site with a higher severity, which would
// win the dedup key and take the CWE row out of the persisted set if it were
// removed after dedup rather than before.

func TestValidMappingResultPersistsNoCopies(t *testing.T) {
	table := map[string][]mappingCat{"CWE-798": {catA07}}
	copies := []map[string]interface{}{
		{"severity": "high", "category": "A07",
			"title": "A07 Authentication Failures: hardcoded credential", "description": "d",
			"file_path": "auth.go", "line_start": 4, "line_end": 4, "recommendation": "r",
			"provenance": "skill", "check_id": "owasp.A07.cwe_798"},
		{"severity": "critical", "category": "CWE-798",
			"title": "A07 copy of the hardcoded credential", "description": "d",
			"file_path": "main.go", "line_start": 1, "line_end": 1, "recommendation": "r",
			"provenance": "skill", "check_id": "owasp.A07.cwe_798"},
	}
	cwe := newScriptedAgent(t, mappingCWEResult)
	owasp := newScriptedAgent(t, legacyOwaspCopy,
		owaspMappingResult(t, "2025", nil, table, map[string]interface{}{"findings": copies}))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	// Scan 1 (legacy agent). Its auth.go copy owns no lineage (0096 M1), so
	// the OWASP row scan 2 must leave alone is one a pre-0096 backend left.
	h.run(t, []string{"cwe", "owasp"}, nil)
	owaspRow := h.seedPre0096OwaspRow(t)
	_, before := lineageDetail(t, h.addr, owaspRow.ID)

	// Scan 2 (valid mapping WITH copies).
	a := h.run(t, []string{"cwe", "owasp"}, nil)
	assertNoOwaspRows(t, a)
	if len(a.Findings) != 1 {
		t.Errorf("persisted %d findings, want the ONE cwe row (no OWASP copies, 0096 I1); findings=%+v", len(a.Findings), a.Findings)
	}
	// Not fatal: the lineage assertions below are a separate guard (I3) and
	// must still report when the persisted set is wrong.
	var cweRow *model.Finding
	for i := range a.Findings {
		if f := a.Findings[i]; f.AgentType == "cwe" && f.Category == "CWE-798" && f.FilePath == "main.go" && f.LineStart == 1 {
			cweRow = &a.Findings[i]
		}
	}
	want := []model.ComplianceLabel{owaspLabel("2025", catA07, "CWE-798")}
	switch {
	case cweRow == nil:
		t.Errorf("the CWE agent's own main.go:1 row must persist, not a copy that won its dedup key: %+v", a.Findings)
	case !reflect.DeepEqual(cweRow.ComplianceLabels, want):
		t.Errorf("cwe row compliance_labels = %+v, want %+v", cweRow.ComplianceLabels, want)
	}

	// Sync point: scan 2's lineage goroutine ran. Normally that is the cwe
	// re-sighting; any row scan 2 touched will do, so a copy that won the cwe
	// row's key still reaches the owasp assertions below instead of a timeout.
	h.waitLineage(t, "a row sighted by scan 2", func(r []labelledLineageRow) bool {
		for _, row := range r {
			if row.LatestAuditID == a.ID {
				return true
			}
		}
		return false
	})
	// Grace window: the owasp pass shares the cwe pass's goroutine.
	time.Sleep(500 * time.Millisecond)
	status, after := lineageDetail(t, h.addr, owaspRow.ID)
	if status != "open" || !reflect.DeepEqual(before, after) {
		t.Fatalf("a mapping-mode result's copies must touch no OWASP lineage row (0096 I1, I3): "+
			"row %s status %q (want open), events before %v, after %v", owaspRow.ID, status, before, after)
	}
	owaspRows := rowsOfAgent(h.lineage(t), "owasp")
	if len(owaspRows) != 1 || owaspRows[0].LatestAuditID == a.ID {
		t.Errorf("a mapping-mode run must neither create nor re-sight an owasp lineage row: %+v", owaspRows)
	}
}
