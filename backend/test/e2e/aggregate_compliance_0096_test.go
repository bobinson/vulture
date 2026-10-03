//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 §7.3 — the target aggregate filters by compliance category.
//
// From 0096 on, OWASP is a set of LABELS on CWE-categorised findings rather
// than a second copy of each row, so "show me this codebase's A07 findings"
// can no longer be answered with `agent_type = owasp`. The aggregate gains
// `framework=owasp&category=A07&edition=2025`, evaluated in SQL against the
// lineage row's per-edition labels (`finding_lineage.compliance_labels`,
// {"owasp:2025": ["A07"], ...}), and every row it returns carries those labels
// so the page can render chips without a second request.
//
// Rules pinned here:
//   - edition given: only that edition's categories match. A07 in 2021 and A07
//     in 2025 are different categories, and a row labelled A07 only under 2021
//     is not an A07:2025 finding.
//   - edition omitted: a 400. A category id means different things in
//     different editions (A03 is Injection in 2021 but Software Supply Chain
//     Failures in 2025), so matching it under every edition would merge
//     unrelated categories into one report. The backend never embeds an
//     edition (§1 I5), so it cannot pick a default either: the caller names it.
//   - the filter composes with the existing ones (status, severity) and, like
//     them, does not move the tiles, which describe the target.
//   - parameters are validated with the same patterns the mapping validator
//     applies (§3.4): framework == "owasp", category ^A\d{2}$, edition ^\d{4}$.
//     A malformed value is a 400 naming the parameter — silently dropping it
//     would answer "all findings" to a question about one category.

// labelledAggRow is the part of an aggregate row this test reads.
type labelledAggRow struct {
	LineageID        string              `json:"lineage_id"`
	Category         string              `json:"category"`
	Status           string              `json:"status"`
	ComplianceLabels map[string][]string `json:"compliance_labels"`
}

type labelledAggResponse struct {
	Total int              `json:"total"`
	Tiles aggTiles         `json:"tiles"`
	Rows  []labelledAggRow `json:"rows"`
}

// seedLabelled plants one lineage row carrying per-edition labels and records
// it under its seed label.
func (w *aggWorld) seedLabelled(label string, tgt aggTarget, auditID string, status model.LineageStatus,
	sev model.Severity, category string, labels map[string][]string) {
	w.t.Helper()
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	l := &model.FindingLineage{
		Fingerprint: "fp-v1-" + label, FingerprintV2: "fp-v2-" + label,
		SourcePath: tgt.Root, AgentType: "cwe", CurrentStatus: status,
		FirstAuditID: auditID, FirstFoundAt: at, LatestAuditID: auditID, LatestFoundAt: &at,
		Severity: string(sev), Category: category, Title: "seeded finding " + label,
		FilePath: "src/" + label + ".py", Provenance: "skill", TargetKey: tgt.Key,
		GitBranch: "main", SeenCount: 1, LastSeenAuditID: auditID,
		EvidenceLineStart: 4, EvidenceLineEnd: 4, ComplianceLabels: labels,
	}
	if status == model.LineageStatusFixed {
		l.FixedAuditID = auditID
		l.FixedAt = &at
	}
	if err := w.lineage.UpsertLineage(l); err != nil {
		w.t.Fatalf("seed lineage %q: %v", label, err)
	}
	w.labels[l.ID] = label
	w.ids[label] = l.ID
}

func (w *aggWorld) labelledAggregate(t *testing.T, tgt aggTarget, query string) labelledAggResponse {
	t.Helper()
	var out labelledAggResponse
	aggGet(t, w.addr, aggregateURL(tgt.Key, query), &out)
	return out
}

func (w *aggWorld) requireLabelledRows(t *testing.T, query string, rows []labelledAggRow, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, r := range rows {
		got[w.labels[r.LineageID]] = true
	}
	wanted := map[string]bool{}
	for _, l := range want {
		wanted[l] = true
	}
	if !reflect.DeepEqual(got, wanted) || len(rows) != len(want) {
		t.Fatalf("?%s returned %v, want %v", query, sortedKeys(got), sortedKeys(wanted))
	}
}

func TestAggregateFiltersByComplianceCategory(t *testing.T) {
	w := newAggWorld(t)
	tgt := w.target("labelled-app")
	other := w.target("other-app")
	w.scan(tgt, "audit-lab-1", "", "main", time.Now().Add(-2*time.Hour), "cwe", "owasp")
	w.scan(other, "audit-oth-1", "", "main", time.Now().Add(-2*time.Hour), "cwe", "owasp")

	open := model.LineageStatusOpen
	seeds := map[string]map[string][]string{
		"sqli":          {"owasp:2025": {"A05"}, "owasp:2021": {"A03"}},
		"secret":        {"owasp:2025": {"A07"}, "owasp:2021": {"A07"}},
		"multi":         {"owasp:2025": {"A01", "A07"}},
		"only-2021":     {"owasp:2021": {"A07"}},
		"empty-edition": {"owasp:2025": {}},
	}
	w.seedLabelled("sqli", tgt, "audit-lab-1", open, model.SeverityHigh, "CWE-89", seeds["sqli"])
	w.seedLabelled("secret", tgt, "audit-lab-1", open, model.SeverityCritical, "CWE-798", seeds["secret"])
	w.seedLabelled("multi", tgt, "audit-lab-1", open, model.SeverityMedium, "CWE-284", seeds["multi"])
	w.seedLabelled("only-2021", tgt, "audit-lab-1", open, model.SeverityHigh, "CWE-287", seeds["only-2021"])
	w.seedLabelled("empty-edition", tgt, "audit-lab-1", open, model.SeverityLow, "CWE-1004", seeds["empty-edition"])
	w.seedLabelled("unlabelled", tgt, "audit-lab-1", open, model.SeverityHigh, "CWE-506", nil)
	w.seedLabelled("closed-secret", tgt, "audit-lab-1", model.LineageStatusFixed, model.SeverityHigh,
		"CWE-798", map[string][]string{"owasp:2025": {"A07"}})
	w.seedLabelled("other-target", other, "audit-oth-1", open, model.SeverityHigh,
		"CWE-798", map[string][]string{"owasp:2025": {"A07"}})
	w.serve()

	unfiltered := w.labelledAggregate(t, tgt, "")
	w.requireLabelledRows(t, "", unfiltered.Rows, "sqli", "secret", "multi", "only-2021", "empty-edition", "unlabelled")

	t.Run("rows carry compliance_labels", func(t *testing.T) {
		for _, r := range unfiltered.Rows {
			label := w.labels[r.LineageID]
			want := seeds[label]
			if !reflect.DeepEqual(r.ComplianceLabels, want) {
				t.Errorf("row %s compliance_labels = %v, want %v", label, r.ComplianceLabels, want)
			}
		}
		code, body := aggFetch(t, w.addr, aggregateURL(tgt.Key, ""))
		if code != http.StatusOK {
			t.Fatalf("unfiltered aggregate: %d", code)
		}
		var raw struct {
			Rows []map[string]json.RawMessage `json:"rows"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, r := range raw.Rows {
			var id string
			_ = json.Unmarshal(r["lineage_id"], &id)
			if w.labels[id] != "unlabelled" {
				continue
			}
			if v, present := r["compliance_labels"]; present {
				t.Errorf("an unlabelled row must omit compliance_labels, got %s", v)
			}
		}
	})

	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"framework=owasp&category=A07&edition=2025", []string{"secret", "multi"}},
		{"framework=owasp&category=A07&edition=2021", []string{"secret", "only-2021"}},
		{"framework=owasp&category=A03&edition=2021", []string{"sqli"}},
		{"framework=owasp&category=A03&edition=2025", nil},
		{"framework=owasp&category=A09&edition=2025", nil},
		{"framework=owasp&category=A07&edition=2025&status=all", []string{"secret", "multi", "closed-secret"}},
		{"framework=owasp&category=A07&edition=2021&severity=critical", []string{"secret"}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			got := w.labelledAggregate(t, tgt, tc.query)
			w.requireLabelledRows(t, tc.query, got.Rows, tc.want...)
			if got.Total != len(tc.want) {
				t.Errorf("?%s total = %d, want %d (the count must be computed from the same filtered set)",
					tc.query, got.Total, len(tc.want))
			}
			if got.Tiles != unfiltered.Tiles {
				t.Errorf("?%s moved the tiles: %+v, want the target's %+v", tc.query, got.Tiles, unfiltered.Tiles)
			}
		})
	}

	t.Run("paging over the filtered set", func(t *testing.T) {
		q := "framework=owasp&category=A07&edition=2025&status=all&page_size=1&page=3"
		got := w.labelledAggregate(t, tgt, q)
		if got.Total != 3 || len(got.Rows) != 1 {
			t.Fatalf("?%s: total %d rows %d, want 3 / 1", q, got.Total, len(got.Rows))
		}
	})

	for _, tc := range []struct {
		query string
		param string
	}{
		{"framework=nist&category=A07", "framework"},
		{"framework=OWASP&category=A07", "framework"},
		{"framework=owasp&category=A7", "category"},
		{"framework=owasp&category=a07", "category"},
		{"framework=owasp&category=A071", "category"},
		{"framework=owasp&category=A07'--", "category"},
		{"framework=owasp&category=A07&edition=25", "edition"},
		{"framework=owasp&category=A07&edition=20251", "edition"},
		{"framework=owasp&category=A07&edition=%25", "edition"},
		{"category=A07", "framework"},
		{"edition=2025", "framework"},
		{"framework=owasp", "category"},
		{"framework=owasp&edition=2025", "category"},
		{"framework=owasp&category=A07", "edition"},
		{"framework=owasp&category=A03", "edition"},
		{"framework=owasp&category=A07&edition=", "edition"},
	} {
		t.Run("rejects "+tc.query, func(t *testing.T) {
			code, body := aggFetch(t, w.addr, aggregateURL(tgt.Key, tc.query))
			if code != http.StatusBadRequest {
				t.Fatalf("?%s: status %d, want 400 — body: %s", tc.query, code, trimForLog(body))
			}
			if !strings.Contains(string(body), tc.param) {
				t.Errorf("?%s: the 400 must name the offending parameter %q — body: %s",
					tc.query, tc.param, trimForLog(body))
			}
		})
	}
}
