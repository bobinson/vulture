//go:build integration

// Feature 0096 §7.3 — the aggregate's compliance-category filter, on Postgres.
//
// The SQLite half of the contract is test/e2e/aggregate_compliance_0096_test.go.
// This file exists because the filter is dialect-specific SQL (jsonb_each and
// the jsonb `?` operator here, json_each there), and the Postgres fragment
// compiles, vets and passes every SQLite test while being wrong.
//
// The second test measures the filter against the §10.1 budget (p95 < 200ms
// for a 50-row page) on the same corpus shape TestPGAggregatePerformanceAtScale
// uses, with labels on every row — v1 ships the filter without an index
// (§4.3), so this number is what decides whether one is needed.
package repository

import (
	"sort"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/model"
)

// labelRows sets compliance_labels on the given lineage rows.
func (f *pgTargetFixture) labelRows(labels map[string]string) {
	f.t.Helper()
	for id, raw := range labels {
		if _, err := f.owner.DB().Exec(
			`UPDATE finding_lineage SET compliance_labels = $1::jsonb WHERE id = $2`, raw, id); err != nil {
			f.t.Fatalf("label row %s: %v", id, err)
		}
	}
}

func TestPGAggregateFiltersByComplianceCategory(t *testing.T) {
	f := newPGTargetFixture(t)
	key := f.target("labelled", 2)
	other := f.target("other", 1)

	open := model.LineageStatusOpen
	ids := f.bulkSeed(key, []pgLineageSeed{
		{status: open, severity: "high", provenance: "skill", seenCount: 1},                     // 0 sqli
		{status: open, severity: "critical", provenance: "skill", seenCount: 1},                 // 1 secret
		{status: open, severity: "medium", provenance: "skill", seenCount: 1},                   // 2 multi
		{status: open, severity: "high", provenance: "skill", seenCount: 1},                     // 3 only-2021
		{status: open, severity: "low", provenance: "skill", seenCount: 1},                      // 4 empty edition
		{status: open, severity: "high", provenance: "skill", seenCount: 1},                     // 5 unlabelled
		{status: model.LineageStatusFixed, severity: "high", provenance: "skill", seenCount: 1}, // 6 closed
	}, 5000)
	otherIDs := f.bulkSeed(other, []pgLineageSeed{{status: open, severity: "high", provenance: "skill", seenCount: 1}}, 6000)
	f.labelRows(map[string]string{
		ids[0]:      `{"owasp:2025":["A05"],"owasp:2021":["A03"]}`,
		ids[1]:      `{"owasp:2025":["A07"],"owasp:2021":["A07"]}`,
		ids[2]:      `{"owasp:2025":["A01","A07"]}`,
		ids[3]:      `{"owasp:2021":["A07"]}`,
		ids[4]:      `{"owasp:2025":[]}`,
		ids[6]:      `{"owasp:2025":["A07"]}`,
		otherIDs[0]: `{"owasp:2025":["A07"]}`,
	})
	name := map[string]string{ids[0]: "sqli", ids[1]: "secret", ids[2]: "multi", ids[3]: "only-2021",
		ids[4]: "empty-edition", ids[5]: "unlabelled", ids[6]: "closed", otherIDs[0]: "other-target"}

	query := func(cat, edition string, terminal bool, sev ...string) model.AggregateQuery {
		return model.AggregateQuery{TargetKey: key, Framework: model.ComplianceFrameworkOWASP,
			Category: cat, Edition: edition, IncludeTerminal: terminal, Severities: sev, Page: 1, PageSize: 50}
	}
	unfiltered, err := f.repo.AggregateByTarget(model.AggregateQuery{TargetKey: key, Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("unfiltered aggregate: %v", err)
	}
	for _, r := range unfiltered.Rows {
		switch name[r.LineageID] {
		case "secret":
			if got := r.ComplianceLabels["owasp:2021"]; len(got) != 1 || got[0] != "A07" {
				t.Errorf("secret row labels = %v, want owasp:2021 [A07] projected from JSONB", r.ComplianceLabels)
			}
		case "unlabelled":
			if r.ComplianceLabels != nil {
				t.Errorf("unlabelled row labels = %v, want nil (NULL column)", r.ComplianceLabels)
			}
		}
	}

	for _, tc := range []struct {
		label string
		query model.AggregateQuery
		want  []string
	}{
		{"A07:2025", query("A07", "2025", false), []string{"multi", "secret"}},
		{"A07:2021", query("A07", "2021", false), []string{"only-2021", "secret"}},
		// The handler requires an edition; a query that reaches the repository
		// without one matches no key rather than every edition's.
		{"A07 no edition", query("A07", "", false), nil},
		{"A03:2021", query("A03", "2021", false), []string{"sqli"}},
		{"A03:2025", query("A03", "2025", false), nil},
		{"A07:2025 status=all", query("A07", "2025", true), []string{"closed", "multi", "secret"}},
		{"A07:2021 + severity", query("A07", "2021", false, "critical"), []string{"secret"}},
	} {
		report, err := f.repo.AggregateByTarget(tc.query)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		got := make([]string, 0, len(report.Rows))
		for _, r := range report.Rows {
			got = append(got, name[r.LineageID])
		}
		sort.Strings(got)
		if len(got) != len(tc.want) || report.Total != len(tc.want) {
			t.Errorf("%s: rows %v total %d, want %v", tc.label, got, report.Total, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: rows %v, want %v", tc.label, got, tc.want)
				break
			}
		}
		if report.Tiles != unfiltered.Tiles {
			t.Errorf("%s: tiles %+v moved with the filter, want %+v", tc.label, report.Tiles, unfiltered.Tiles)
		}
	}
}

// TestPGAggregateComplianceFilterLatency measures the filtered read against
// the 200ms p95 budget on a ~10k-row labelled corpus.
func TestPGAggregateComplianceFilterLatency(t *testing.T) {
	f := newPGTargetFixture(t)
	statuses := []model.LineageStatus{
		model.LineageStatusOpen, model.LineageStatusInProgress, model.LineageStatusRegression,
		model.LineageStatusUnconfirmed, model.LineageStatusFixed, model.LineageStatusResolved,
	}
	severities := []string{"critical", "high", "medium", "low", "info"}
	labelShapes := []string{
		`{"owasp:2025":["A07"],"owasp:2021":["A07"]}`,
		`{"owasp:2025":["A05"],"owasp:2021":["A03"]}`,
		`{"owasp:2025":["A01","A07"]}`,
		`{"owasp:2021":["A02"]}`,
		``, // unlabelled
	}

	const perTarget = 2600
	var biggest string
	ref := 1
	for ti, tname := range []string{"alpha", "beta", "gamma", "delta"} {
		key := f.target(tname, 5)
		if ti == 0 {
			biggest = key
		}
		seeds := make([]pgLineageSeed, 0, perTarget)
		for i := range perTarget {
			seeds = append(seeds, pgLineageSeed{status: statuses[i%len(statuses)],
				severity: severities[i%len(severities)], provenance: "skill", seenCount: 1 + i%7, auditIdx: i % 5})
		}
		ids := f.bulkSeed(key, seeds, ref)
		ref += perTarget
		f.seedEvents(ids)
		if _, err := f.owner.DB().Exec(`UPDATE finding_lineage
			SET compliance_labels = (ARRAY[`+quoteShapes(labelShapes)+`])[1 + (ref_number % $1)]::jsonb
			WHERE target_key = $2`, len(labelShapes), key); err != nil {
			t.Fatalf("label corpus: %v", err)
		}
	}
	if _, err := f.owner.DB().Exec(`ANALYZE finding_lineage`); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	for _, tc := range []struct {
		label string
		query model.AggregateQuery
	}{
		{"A07:2025 active", model.AggregateQuery{TargetKey: biggest, Framework: "owasp", Category: "A07", Edition: "2025", Page: 1, PageSize: 50}},
		{"A07:2021, all", model.AggregateQuery{TargetKey: biggest, Framework: "owasp", Category: "A07", Edition: "2021", IncludeTerminal: true, Page: 1, PageSize: 50}},
		{"A07:2025 deep page", model.AggregateQuery{TargetKey: biggest, Framework: "owasp", Category: "A07", Edition: "2025", IncludeTerminal: true, Page: 10, PageSize: 50}},
		{"A02:2021 + severity", model.AggregateQuery{TargetKey: biggest, Framework: "owasp", Category: "A02", Edition: "2021", IncludeTerminal: true, Severities: []string{"medium", "low"}, Page: 1, PageSize: 50}},
	} {
		report, err := f.repo.AggregateByTarget(tc.query)
		if err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if report.Total == 0 {
			t.Fatalf("%s: the filter matched nothing; the measurement would be vacuous", tc.label)
		}
		p50, p95 := f.measure(tc.query)
		t.Logf("aggregate+compliance %-22s total=%4d  p50=%6.2fms  p95=%6.2fms", tc.label, report.Total,
			float64(p50.Microseconds())/1000, float64(p95.Microseconds())/1000)
		if p95 > 200*time.Millisecond {
			t.Errorf("%s: p95 %.2fms exceeds the 200ms budget", tc.label, float64(p95.Microseconds())/1000)
		}
	}
}

// quoteShapes renders the label shapes as a SQL text-array literal body; ""
// becomes NULL (an unlabelled row).
func quoteShapes(shapes []string) string {
	out := ""
	for i, s := range shapes {
		if i > 0 {
			out += ","
		}
		if s == "" {
			out += "NULL"
			continue
		}
		out += "'" + s + "'"
	}
	return out
}
