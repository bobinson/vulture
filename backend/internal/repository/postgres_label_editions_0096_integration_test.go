//go:build integration

package repository

import (
	"reflect"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 M8, Postgres half of TestAggregateReportsLabelEditions (e2e):
// the aggregate names the framework:edition keys — and the categories under
// each — that the target's lineage rows carry, over the target scope (every
// status, unaffected by the report filters), newest edition first.
func TestPGAggregateReportsLabelEditions(t *testing.T) {
	f := newPGTargetFixture(t)
	key := f.target("editions", 1)
	other := f.target("editions-other", 1)
	bare := f.target("editions-bare", 1)
	open := model.LineageStatusOpen
	ids := f.bulkSeed(key, []pgLineageSeed{
		{status: open, severity: "high", provenance: "skill", seenCount: 1},
		{status: open, severity: "critical", provenance: "skill", seenCount: 1},
		{status: model.LineageStatusFixed, severity: "high", provenance: "skill", seenCount: 1},
		{status: open, severity: "low", provenance: "skill", seenCount: 1},
		{status: open, severity: "low", provenance: "skill", seenCount: 1}, // unlabelled
		{status: open, severity: "low", provenance: "skill", seenCount: 1}, // non-object labels
	}, 7000)
	otherIDs := f.bulkSeed(other, []pgLineageSeed{{status: open, severity: "high", provenance: "skill", seenCount: 1}}, 8000)
	f.bulkSeed(bare, []pgLineageSeed{{status: open, severity: "high", provenance: "skill", seenCount: 1}}, 9000)
	f.labelRows(map[string]string{
		ids[0]:      `{"owasp:2025":["A05"],"owasp:2021":["A03"]}`,
		ids[1]:      `{"owasp:2025":["A07"],"owasp:2021":["A07"]}`,
		ids[2]:      `{"owasp:2025":["A09"]}`,
		ids[3]:      `{"owasp:2017":[]}`,
		ids[5]:      `["A01"]`,
		otherIDs[0]: `{"owasp:2030":["A01"]}`,
	})

	want := []model.LabelEdition{
		{Framework: "owasp", Edition: "2025", Categories: []string{"A05", "A07", "A09"}},
		{Framework: "owasp", Edition: "2021", Categories: []string{"A03", "A07"}},
		{Framework: "owasp", Edition: "2017", Categories: []string{}},
	}
	for label, q := range map[string]model.AggregateQuery{
		"unfiltered": {TargetKey: key, Page: 1, PageSize: 50},
		"category filter": {TargetKey: key, Framework: model.ComplianceFrameworkOWASP, Category: "A07",
			Edition: "2025", Page: 1, PageSize: 50},
		"severity filter": {TargetKey: key, Severities: []string{"low"}, Page: 1, PageSize: 50},
	} {
		report, err := f.repo.AggregateByTarget(q)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if !reflect.DeepEqual(report.LabelEditions, want) {
			t.Errorf("%s: label_editions = %+v, want %+v", label, report.LabelEditions, want)
		}
	}
	for label, k := range map[string]string{"unlabelled target": bare, "unknown target": "marker:nope"} {
		report, err := f.repo.AggregateByTarget(model.AggregateQuery{TargetKey: k, Page: 1, PageSize: 50})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if report.LabelEditions == nil || len(report.LabelEditions) != 0 {
			t.Errorf("%s: label_editions = %#v, want empty non-nil", label, report.LabelEditions)
		}
	}
}
