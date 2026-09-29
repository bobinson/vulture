package repository

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096: the label codec is the storage boundary for both dialects, so
// it owns the dbSafeText rule. A NUL survives json.Marshal as `\u0000`, which
// SQLite TEXT accepts and Postgres jsonb rejects — for the whole multi-row
// statement it rides in (see dbSafeText).
func TestLabelColumnsCarryNoNUL(t *testing.T) {
	finding := findingLabelsColumn([]model.ComplianceLabel{{Framework: "ow\x00asp", Edition: "20\x0025",
		CategoryID: "A0\x007", CategoryName: "Auth\x00", CWE: "CWE-\x00798"}})
	lineage := lineageLabelsColumn(map[string][]string{"owasp:\x002025": {"A\x0007"}, "owasp:2021": nil})
	for name, v := range map[string]interface{}{"finding": finding, "lineage": lineage} {
		s, _ := v.(string)
		if s == "" || strings.Contains(s, `\u0000`) || strings.IndexByte(s, 0) >= 0 {
			t.Errorf("%s labels column = %q, want JSON with no NUL", name, s)
		}
	}
	if want := `[{"framework":"owasp","edition":"2025","category_id":"A07","category_name":"Auth","cwe":"CWE-798"}]`; finding != want {
		t.Errorf("finding labels column = %v, want %s", finding, want)
	}
	if want := `{"owasp:2021":[],"owasp:2025":["A07"]}`; lineage != want {
		t.Errorf("lineage labels column = %v, want %s", lineage, want)
	}
}
