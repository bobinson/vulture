//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

// Feature 0096 P1, hardening. Three contract edges the first P1 tests left
// open: the coverage manifest of a `selected` subset run (LLD §3.3), a
// `mapping` key that is present but not an object (§2.2, §3.4, I3), and
// validation variants that would label a persisted finding if their rule were
// removed — so the rule, not an accident of the fixture, is what they pin.

func TestCoverageOnSubsetRunCountsOnlyAppliedLabels(t *testing.T) {
	// LLD §3.3: found_count(cat) is the number of distinct CWE ids among the
	// persisted findings LABELLED cat. The audit selected A07 only, so no
	// persisted row carries A04 or A05 — the agent's manifest (computed over
	// every category, as build_manifest does) says both were found. A coverage
	// card that claims A05 "found" while no row carries A05 is the R10
	// mismatch; an unselected category must say it was not selected rather
	// than look clean.
	table := map[string][]mappingCat{
		"CWE-798": {catA07},
		"CWE-89":  {catA05},
		"CWE-259": {catA07, catA04},
	}
	agentManifest := map[string]interface{}{
		"edition":          "2025",
		"cwe_stage_status": "completed",
		"categories": []map[string]interface{}{
			{"id": "A04", "name": "Cryptographic Failures", "mapped_count": 30, "found_cwes": []string{"CWE-259"},
				"found_count": 1, "status": "found", "source_url": "https://owasp.example/A04"},
			{"id": "A05", "name": "Injection", "mapped_count": 37, "found_cwes": []string{"CWE-89"},
				"found_count": 1, "status": "found", "source_url": "https://owasp.example/A05"},
			{"id": "A07", "name": "Authentication Failures", "mapped_count": 36, "found_cwes": []string{"CWE-259", "CWE-798"},
				"found_count": 2, "status": "found", "source_url": "https://owasp.example/A07"},
		},
		"unmapped_cwes":  []string{},
		"unmapped_count": 0,
	}
	cwe := newScriptedAgent(t, scanResult(t, rowSecret, rowSQLi,
		scanFinding{"CWE-259", "Hard-coded password", "auth.go", 4}))
	owasp := newScriptedAgent(t, owaspMappingResult(t, "2025", []string{"A07"}, table,
		map[string]interface{}{"owasp_coverage": agentManifest}))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe, "owasp": owasp})

	a := h.run(t, []string{"cwe", "owasp"}, map[string]interface{}{
		"owasp": map[string]interface{}{"categories": []string{"A07"}},
	})

	labelled := map[string][]string{}
	for _, f := range a.Findings {
		for _, l := range f.ComplianceLabels {
			labelled[l.CategoryID] = append(labelled[l.CategoryID], l.CWE)
		}
	}
	var manifest struct {
		Categories []map[string]json.RawMessage `json:"categories"`
	}
	if err := json.Unmarshal(a.OwaspCoverage, &manifest); err != nil || len(manifest.Categories) != 3 {
		t.Fatalf("persisted owasp_coverage %s: %v", a.OwaspCoverage, err)
	}
	want := map[string]struct {
		found    []string
		status   string
		selected bool
	}{
		"A04": {[]string{}, "clean-or-undetected", false},
		"A05": {[]string{}, "clean-or-undetected", false},
		"A07": {[]string{"CWE-259", "CWE-798"}, "found", true},
	}
	for _, raw := range manifest.Categories {
		var c coverageCategory
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &c)
		w := want[c.ID]
		fromLabels := append([]string{}, labelled[c.ID]...)
		sort.Strings(fromLabels)
		if c.FoundCount != len(w.found) || !reflect.DeepEqual(nonNil(c.FoundCWEs), w.found) ||
			!reflect.DeepEqual(nonNil(c.FoundCWEs), fromLabels) {
			t.Errorf("%s: found_count=%d found_cwes=%v, want %v — exactly the CWEs persisted rows are LABELLED %s with (%v)",
				c.ID, c.FoundCount, c.FoundCWEs, w.found, c.ID, fromLabels)
		}
		if c.Status != w.status {
			t.Errorf("%s: status %q, want %q", c.ID, c.Status, w.status)
		}
		sel, marked := raw["selected"]
		switch {
		case w.selected && marked:
			t.Errorf("%s: a selected category carries no marker, got selected=%s", c.ID, sel)
		case !w.selected && string(sel) != "false":
			t.Errorf("%s: an unselected category must say so (selected=false), got %q", c.ID, sel)
		}
		if c.MappedCount == 0 || c.Name == "" || c.SourceURL == "" {
			t.Errorf("%s: the agent's mapped_count/name/source_url must survive: %+v", c.ID, c)
		}
	}
}

func TestNonObjectMappingTouchesNoLineage(t *testing.T) {
	// §2.2 makes the PRESENCE of `mapping` the mode marker and §3.4 says an
	// invalid mapping never falls back to legacy. A `mapping` of the wrong
	// type (null — what `extra={"mapping": None}` serialises to — an array, a
	// string) is an invalid mapping: read as legacy, its empty findings
	// reach the closure pass and close every OWASP row (R1, I3).
	cwe := newScriptedAgent(t, mappingCWEResult)
	withMapping := func(result, mapping string) string {
		return result[:len(result)-1] + `,"mapping":` + mapping + `}`
	}
	cases := []struct{ name, result string }{
		{"null, no findings", withMapping(legacyOwaspEmpty, `null`)},
		{"array, no findings", withMapping(legacyOwaspEmpty, `[]`)},
		{"string, no findings", withMapping(legacyOwaspEmpty, `"v1"`)},
		{"null, with a copy row", withMapping(legacyOwaspCopy, `null`)},
	}
	results := []string{legacyOwaspCopy}
	for _, c := range cases {
		results = append(results, c.result)
	}
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
			assertNoOwaspRows(t, a)
			assertNoLabels(t, a, "a mapping that is not an object labels nothing")
			h.waitLineage(t, "the cwe re-sighting", func(r []labelledLineageRow) bool {
				c := rowsOfAgent(r, "cwe")
				return len(c) == 1 && c[0].LatestAuditID == a.ID
			})
			time.Sleep(500 * time.Millisecond)
			status, after := lineageDetail(t, h.addr, owaspRow.ID)
			if status != "open" {
				t.Fatalf("a non-object mapping closed OWASP lineage row %s: status %q, want open (0096 I3)", owaspRow.ID, status)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("a non-object mapping must record ZERO lineage events on an OWASP row: before %v, after %v", before, after)
			}
		})
	}
}

func TestInvalidMappingVariantsWouldLabelWithoutTheirRule(t *testing.T) {
	// Each rejected variant differs from an ACCEPTED control only in the one
	// rule it breaks, and the control labels the persisted CWE-798 row. So a
	// variant that labels nothing is rejected BY ITS RULE — deleting the rule
	// would let it through and label the row, and this test would fail.
	catA07JSON := `[{"id":"A07","name":"Authentication Failures"}]`
	tableWith := func(filler int) string {
		tbl := make(map[string]json.RawMessage, filler+1)
		for i := 0; i < filler; i++ {
			tbl[fmt.Sprintf("CWE-%d", 10000+i)] = json.RawMessage(catA07JSON)
		}
		tbl["CWE-798"] = json.RawMessage(catA07JSON)
		b, _ := json.Marshal(tbl)
		return string(b)
	}
	mapping := func(selected, table string) string {
		return `{"findings":[],"summary":"owasp","score":80,"mapping":{"version":1,"framework":"owasp",` +
			`"edition":"2025","selected":` + selected + `,"table":` + table + `}}`
	}
	cases := []struct {
		name, result string
		labels       bool
	}{
		{"control: selected A07", mapping(`["A07"]`, tableWith(0)), true},
		{"selected mixes a valid and a malformed id", mapping(`["A07","A7"]`, tableWith(0)), false},
		{"control: exactly 2000 keys", mapping(`[]`, tableWith(1999)), true},
		{"2001 keys, one of them the persisted CWE", mapping(`[]`, tableWith(2000)), false},
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
			assertNoOwaspRows(t, a)
			f := findingByCategory(t, a, "CWE-798")
			if !c.labels {
				assertNoLabels(t, a, "an invalid mapping must be dropped whole")
				return
			}
			if got, want := f.ComplianceLabels, owaspLabel("2025", catA07, "CWE-798"); len(got) != 1 || got[0] != want {
				t.Errorf("the accepted control must label CWE-798 with A07, got %+v", got)
			}
		})
	}
}
