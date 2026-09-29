//go:build e2e

package e2e

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Feature 0096 P1, skew and failure edges of LLD §5 and §3.3. A mapper agent
// that sends neither a mapping nor findings has no evidence to close anything
// on — whether it failed or answered "clean" in legacy mode, where its CWE
// stage may simply have failed (R1, I4). And a mapping-mode run whose mapping
// is rejected labels nothing, so its persisted coverage manifest must not
// claim any category was found (R10).

// withResultMember appends one member to a scripted JSON result object.
func withResultMember(result, key, value string) string {
	return strings.TrimSuffix(result, "}") + `,"` + key + `":` + value + `}`
}

func TestMapperWithNothingToReportTouchesNoLineage(t *testing.T) {
	cases := []struct{ name, result string }{
		{"errored", `{"findings":[],"summary":"owasp","score":0,"error":"boom"}`},
		{"clean legacy, cwe stage failed", withResultMember(legacyOwaspEmpty, "owasp_coverage",
			`{"edition":"2025","cwe_stage_status":"failed","categories":[]}`)},
		{"clean legacy", legacyOwaspEmpty},
	}
	results := []string{legacyOwaspCopy}
	for _, c := range cases {
		results = append(results, c.result)
	}
	// CONTROL: the scan agent answers with an `error` too, and still reaches
	// the closure pass — it re-sights its row. The skip is the mapper's alone.
	cwe := newScriptedAgent(t, mappingCWEResult, withResultMember(mappingCWEResult, "error", `"partial"`))
	owasp := newScriptedAgent(t, results...)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	h.run(t, []string{"cwe", "owasp"}, nil)
	// 0096 M1: scan 1's legacy copy owns no lineage, so the OWASP row these
	// cases must leave alone is one a pre-0096 backend left behind.
	owaspRow := h.seedPre0096OwaspRow(t)
	_, before := lineageDetail(t, h.addr, owaspRow.ID)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := h.run(t, []string{"cwe", "owasp"}, nil)
			h.waitLineage(t, "the errored cwe result re-sighting its row", func(r []labelledLineageRow) bool {
				c := rowsOfAgent(r, "cwe")
				return len(c) == 1 && c[0].LatestAuditID == a.ID
			})
			time.Sleep(500 * time.Millisecond)
			status, after := lineageDetail(t, h.addr, owaspRow.ID)
			if status != "open" {
				t.Fatalf("a mapper that sent neither a mapping nor findings (%s) closed OWASP lineage row %s: "+
					"status %q, want open (0096 §5, I4)", c.name, owaspRow.ID, status)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("a mapper with nothing to report must record ZERO lineage events: before %v, after %v", before, after)
			}
		})
	}
}

func TestRejectedMappingCoverageClaimsNothingFound(t *testing.T) {
	// The agent computes its manifest before dedup and before the backend has
	// validated anything. A rejected mapping leaves ZERO labels and (I1) zero
	// OWASP rows, so by §3.3 no category was found — a card claiming A07
	// "found" would link to nothing. What is not a count stays the agent's.
	manifest := `{"edition":"2025","cwe_stage_status":"completed","categories":[` +
		`{"id":"A05","name":"Injection","mapped_count":37,"found_cwes":[],"found_count":0,` +
		`"status":"clean-or-undetected","source_url":"https://owasp.example/A05"},` +
		`{"id":"A07","name":"Authentication Failures","mapped_count":36,"found_cwes":["CWE-798"],` +
		`"found_count":1,"status":"found","source_url":"https://owasp.example/A07"}],` +
		`"unmapped_cwes":[],"unmapped_count":0}`
	withManifest := func(mapping string) string {
		return `{"findings":[],"summary":"owasp","score":80,"owasp_coverage":` + manifest + `,"mapping":` + mapping + `}`
	}
	cases := []struct{ name, result string }{
		{"version 2", withManifest(`{"version":2,"framework":"owasp","edition":"2025","selected":[],` +
			`"table":{"CWE-798":[{"id":"A07","name":"Authentication Failures"}]}}`)},
		{"mapping null", withManifest(`null`)},
	}
	results := make([]string, len(cases))
	for i, c := range cases {
		results[i] = c.result
	}
	cwe := newScriptedAgent(t, mappingCWEResult)
	owasp := newScriptedAgent(t, results...)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := h.run(t, []string{"cwe", "owasp"}, nil)
			assertNoLabels(t, a, "a rejected mapping labels nothing")
			assertNoOwaspRows(t, a)
			var got struct {
				Edition        string             `json:"edition"`
				CWEStageStatus string             `json:"cwe_stage_status"`
				Categories     []coverageCategory `json:"categories"`
			}
			if err := json.Unmarshal(a.OwaspCoverage, &got); err != nil {
				t.Fatalf("persisted owasp_coverage %s: %v", a.OwaspCoverage, err)
			}
			if got.Edition != "2025" || got.CWEStageStatus != "completed" || len(got.Categories) != 2 {
				t.Fatalf("the manifest's provenance must stay the agent's: %s", a.OwaspCoverage)
			}
			for _, cat := range got.Categories {
				if cat.FoundCount != 0 || len(cat.FoundCWEs) != 0 || cat.Status != "clean-or-undetected" {
					t.Errorf("%s: found_count=%d found_cwes=%v status=%q with ZERO persisted labels; "+
						"a rejected mapping must not report a category found (0096 §3.3, R10)",
						cat.ID, cat.FoundCount, cat.FoundCWEs, cat.Status)
				}
				if cat.MappedCount == 0 || cat.Name == "" || cat.SourceURL == "" {
					t.Errorf("%s: the agent's mapped_count/name/source_url must survive: %+v", cat.ID, cat)
				}
			}
		})
	}
}
