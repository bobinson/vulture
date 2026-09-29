//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 M8 — the aggregate names the label editions the target holds.
//
// The compliance filter needs framework, category AND edition together (a
// category id means different things in different editions), and the backend
// never embeds an edition. So the page can only offer that filter if the
// response says which framework:edition keys — and which categories under
// each — the target's lineage rows actually carry. `label_editions` is that
// list: derived from finding_lineage.compliance_labels of the target within
// the selected scans, every status included (like the tiles, it describes the
// target, not the filtered rows, so choosing a filter never removes the
// option to change it), ordered by framework then newest edition first, and
// always present — `[]` when nothing is labelled.

type labelEdition struct {
	Framework  string   `json:"framework"`
	Edition    string   `json:"edition"`
	Categories []string `json:"categories"`
}

func TestAggregateReportsLabelEditions(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("editions-app")
	other := w.target("editions-other")
	bare := w.target("editions-bare")
	w.scan(tgt, "audit-ed-1", "", "main", time.Now().Add(-2*time.Hour), "cwe", "owasp")
	w.scan(other, "audit-ed-oth", "", "main", time.Now().Add(-2*time.Hour), "cwe", "owasp")
	w.scan(bare, "audit-ed-bare", "", "main", time.Now().Add(-2*time.Hour), "cwe")

	open := model.LineageStatusOpen
	w.seedLabelled("ed-sqli", tgt, "audit-ed-1", open, model.SeverityHigh, "CWE-89",
		map[string][]string{"owasp:2025": {"A05"}, "owasp:2021": {"A03"}})
	w.seedLabelled("ed-secret", tgt, "audit-ed-1", open, model.SeverityCritical, "CWE-798",
		map[string][]string{"owasp:2025": {"A07"}, "owasp:2021": {"A07"}})
	w.seedLabelled("ed-closed", tgt, "audit-ed-1", model.LineageStatusFixed, model.SeverityHigh, "CWE-778",
		map[string][]string{"owasp:2025": {"A09"}})
	w.seedLabelled("ed-empty", tgt, "audit-ed-1", open, model.SeverityLow, "CWE-1004",
		map[string][]string{"owasp:2017": {}})
	w.seedLabelled("ed-unlabelled", tgt, "audit-ed-1", open, model.SeverityLow, "CWE-506", nil)
	w.seedLabelled("ed-corrupt", tgt, "audit-ed-1", open, model.SeverityLow, "CWE-20", nil)
	w.seedLabelled("ed-other", other, "audit-ed-oth", open, model.SeverityHigh, "CWE-798",
		map[string][]string{"owasp:2030": {"A01"}})
	w.seedLabelled("ed-bare", bare, "audit-ed-bare", open, model.SeverityHigh, "CWE-798", nil)
	if _, err := w.base.DB().Exec(`UPDATE finding_lineage SET compliance_labels = '{broken' WHERE id = ?`,
		w.ids["ed-corrupt"]); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}
	w.serve()

	want := []labelEdition{
		{Framework: "owasp", Edition: "2025", Categories: []string{"A05", "A07", "A09"}},
		{Framework: "owasp", Edition: "2021", Categories: []string{"A03", "A07"}},
		{Framework: "owasp", Edition: "2017", Categories: []string{}},
	}
	editionsOf := func(key, query string) ([]labelEdition, bool) {
		t.Helper()
		code, body := aggFetch(t, w.addr, aggregateURL(key, query))
		if code != http.StatusOK {
			t.Fatalf("aggregate ?%s: status %d — %s", query, code, trimForLog(body))
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		field, present := raw["label_editions"]
		var out []labelEdition
		if present {
			if err := json.Unmarshal(field, &out); err != nil {
				t.Fatalf("decode label_editions %s: %v", field, err)
			}
		}
		return out, present && string(field) != "null"
	}

	for _, q := range []string{"", "framework=owasp&category=A07&edition=2025", "severity=low", "status=all"} {
		got, present := editionsOf(tgt.Key, q)
		if !present || !reflect.DeepEqual(got, want) {
			t.Errorf("?%s label_editions = %+v (present=%v), want %+v", q, got, present, want)
		}
	}
	if got, present := editionsOf(bare.Key, ""); !present || len(got) != 0 {
		t.Errorf("an unlabelled target must report label_editions = [], got %+v (present=%v)", got, present)
	}
	if got, present := editionsOf("marker:no-such-target", ""); !present || len(got) != 0 {
		t.Errorf("an unknown target must report label_editions = [], got %+v (present=%v)", got, present)
	}
}
