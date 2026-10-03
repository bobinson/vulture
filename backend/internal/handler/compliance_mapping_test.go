package handler

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 §3 at the unit level: validation, label application, the
// coverage recomputation and the lineage skip rule. The business contract is
// pinned end to end in test/e2e/owasp_mapping_labels_test.go; these pin the
// pieces the E2E suite reaches only through one fixture each.

const validMapping = `{"version":1,"framework":"owasp","edition":"2025","selected":[],` +
	`"table":{"CWE-798":[{"id":"A07","name":"Authentication Failures"},{"id":"A07","name":"Authentication Failures"}],` +
	`"CWE-89":[{"id":"A05","name":"Injection"}]}}`

func TestParseComplianceMappingFoldsDuplicateCategories(t *testing.T) {
	m, err := parseComplianceMapping(json.RawMessage(validMapping))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Framework != "owasp" || m.Edition != "2025" || m.LineageKey() != "owasp:2025" {
		t.Fatalf("header = %+v", m)
	}
	if got := m.Table["CWE-798"]; len(got) != 1 || got[0].ID != "A07" {
		t.Fatalf("a repeated category id must be folded to one label: %+v", got)
	}
}

func TestParseComplianceMappingRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"missing table": `{"version":1,"framework":"owasp","edition":"2025"}`,
		"null table":    `{"version":1,"framework":"owasp","edition":"2025","table":null}`,
		"version 0":     `{"framework":"owasp","edition":"2025","table":{}}`,
		"cwe key six digits": `{"version":1,"framework":"owasp","edition":"2025",` +
			`"table":{"CWE-123456":[]}}`,
		"name multibyte over cap": `{"version":1,"framework":"owasp","edition":"2025",` +
			`"table":{"CWE-1":[{"id":"A01","name":"` + strings.Repeat("é", 121) + `"}]}}`,
		"selected malformed": `{"version":1,"framework":"owasp","edition":"2025","selected":["A07","A7"],` +
			`"table":{"CWE-798":[{"id":"A07","name":"Authentication Failures"}]}}`,
		"table 2001 keys": mappingWithKeys(2001),
		"not an object":   `[]`,
		"null":            `null`,
	} {
		if m, err := parseComplianceMapping(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted %+v, want rejection", name, m)
		}
	}
	// The cap is in characters, not bytes: 120 two-byte runes are legal.
	ok := `{"version":1,"framework":"owasp","edition":"2025",` +
		`"table":{"CWE-1":[{"id":"A01","name":"` + strings.Repeat("é", 120) + `"}]}}`
	if _, err := parseComplianceMapping(json.RawMessage(ok)); err != nil {
		t.Errorf("120 characters must be accepted: %v", err)
	}
	if _, err := parseComplianceMapping(json.RawMessage(mappingWithKeys(maxMappingTableKeys))); err != nil {
		t.Errorf("exactly %d keys must be accepted: %v", maxMappingTableKeys, err)
	}
}

// mappingWithKeys renders a valid mapping whose table has exactly n keys.
func mappingWithKeys(n int) string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf(`"CWE-%d":[{"id":"A05","name":"Injection"}]`, 10000+i)
	}
	return `{"version":1,"framework":"owasp","edition":"2025","table":{` + strings.Join(keys, ",") + `}}`
}

func TestExtractOwaspMappingOnlyFromTheOwaspSnapshot(t *testing.T) {
	snap := json.RawMessage(`{"findings":[],"mapping":` + validMapping + `}`)
	for _, evt := range []*model.AgUIEvent{
		{Type: model.EventStateSnapshot, AgentType: "cwe", Snapshot: snap},
		{Type: model.EventStateDelta, AgentType: "owasp", Snapshot: snap},
		{Type: model.EventStateSnapshot, AgentType: "owasp", Snapshot: json.RawMessage(`{"findings":[]}`)},
		nil,
	} {
		if m, _ := extractOwaspMapping(evt); m != nil {
			t.Errorf("event %+v yielded a mapping; only the owasp result snapshot may", evt)
		}
	}
	m, mode := extractOwaspMapping(&model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: "owasp", Snapshot: snap})
	if m == nil || !mode || len(m.Table) != 2 {
		t.Fatalf("owasp snapshot: mapping = %+v mode=%v", m, mode)
	}
}

// A `mapping` key of the wrong type is an INVALID mapping, not an absent
// one (§2.2, §3.4): mapping mode with no labels, never legacy.
func TestExtractOwaspMappingNonObjectIsInvalidMappingMode(t *testing.T) {
	for _, v := range []string{`null`, `[]`, `"v1"`, `7`} {
		evt := &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: "owasp",
			Snapshot: json.RawMessage(`{"findings":[],"mapping":` + v + `}`)}
		if m, mode := extractOwaspMapping(evt); m != nil || !mode {
			t.Errorf("mapping=%s: got (%+v, %v), want (nil, true)", v, m, mode)
		}
	}
}

func TestNoteOwaspAnswerModeIsPresenceNotValidity(t *testing.T) {
	valid := mustMapping(t, validMapping)
	outcomes := map[string]*model.ScanResult{"owasp": {}}
	invalid := &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: "owasp",
		Snapshot: json.RawMessage(`{"findings":[],"mapping":{"version":99}}`)}
	if m := noteOwaspAnswer(invalid, nil, outcomes, valid); m != nil || !outcomes["owasp"].MappingMode {
		t.Fatalf("an invalid mapping is still mapping mode, and replaces any earlier mapping with none: "+
			"mode=%v m=%+v", outcomes["owasp"].MappingMode, m)
	}
	outcomes = map[string]*model.ScanResult{"cwe": {}}
	other := &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: "cwe",
		Snapshot: json.RawMessage(`{"findings":[],"mapping":` + validMapping + `}`)}
	if m := noteOwaspAnswer(other, nil, outcomes, valid); m != valid || outcomes["cwe"].MappingMode {
		t.Fatalf("a scan agent's snapshot changes neither the mapping nor its own mode: mode=%v m=%+v",
			outcomes["cwe"].MappingMode, m)
	}
}

func mustMapping(t *testing.T, raw string) *model.ComplianceMapping {
	t.Helper()
	m, err := parseComplianceMapping(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return m
}

func TestApplyComplianceMapping(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":["A07"],`+
		`"table":{"CWE-798":[{"id":"A07","name":"Auth"}],"CWE-259":[{"id":"A07","name":"Auth"},{"id":"A04","name":"Crypto"}],`+
		`"CWE-89":[{"id":"A05","name":"Injection"}]}}`)
	other := model.ComplianceLabel{Framework: "asvs", Edition: "5", CategoryID: "V2", CWE: "CWE-798"}
	stale := model.ComplianceLabel{Framework: "owasp", Edition: "2025", CategoryID: "A01", CWE: "CWE-798"}
	findings := []model.Finding{
		{AgentType: "cwe", Category: "CWE-798", ComplianceLabels: []model.ComplianceLabel{other, stale}},
		{AgentType: "xss", Category: "CWE-259", IsRollup: true},
		{AgentType: "cwe", Category: "CWE-89"},   // mapped, but not selected
		{AgentType: "cwe", Category: "CWE-1234"}, // not mapped
		{AgentType: "owasp", Category: "CWE-798"},
		{AgentType: "chaos", Category: "retry"},
	}
	applyComplianceMapping(findings, m)

	a07 := func(cwe string) model.ComplianceLabel {
		return model.ComplianceLabel{Framework: "owasp", Edition: "2025", CategoryID: "A07", CategoryName: "Auth", CWE: cwe}
	}
	want := [][]model.ComplianceLabel{
		// Another framework's label survives; this edition's is replaced.
		{other, a07("CWE-798")},
		// A rollup parent is labelled like any other CWE row.
		{a07("CWE-259")},
		nil, nil, nil, nil,
	}
	for i, f := range findings {
		if !reflect.DeepEqual(f.ComplianceLabels, want[i]) {
			t.Errorf("finding %d (%s %s): labels %+v, want %+v", i, f.AgentType, f.Category, f.ComplianceLabels, want[i])
		}
	}
}

// agentManifestNoDedup is the OWASP agent's OWN manifest for a four-category
// edition — A01 {22,73}, A04 {259,327}, A05 {79,80,89}, A07 {798,259} —
// over detected CWEs {22,79,89,259,1234}, produced by
// shared.owasp.coverage.build_manifest (the agent's code, not a transcription).
const agentManifestNoDedup = `{"edition":"2025","cwe_stage_status":"completed","categories":[` +
	`{"id":"A01","name":"Broken Access Control","mapped_count":2,"found_cwes":["CWE-22"],"found_count":1,"status":"found","source_url":"u1"},` +
	`{"id":"A04","name":"Cryptographic Failures","mapped_count":2,"found_cwes":["CWE-259"],"found_count":1,"status":"found","source_url":"u4"},` +
	`{"id":"A05","name":"Injection","mapped_count":3,"found_cwes":["CWE-79","CWE-89"],"found_count":2,"status":"found","source_url":"u5"},` +
	`{"id":"A07","name":"Authentication Failures","mapped_count":2,"found_cwes":["CWE-259"],"found_count":1,"status":"found","source_url":"u7"}],` +
	`"unmapped_cwes":["CWE-1234"],"unmapped_count":1}`

const noDedupTable = `"table":{"CWE-22":[{"id":"A01","name":"Broken Access Control"}],` +
	`"CWE-73":[{"id":"A01","name":"Broken Access Control"}],` +
	`"CWE-259":[{"id":"A04","name":"Cryptographic Failures"},{"id":"A07","name":"Authentication Failures"}],` +
	`"CWE-327":[{"id":"A04","name":"Cryptographic Failures"}],` +
	`"CWE-79":[{"id":"A05","name":"Injection"}],"CWE-80":[{"id":"A05","name":"Injection"}],` +
	`"CWE-89":[{"id":"A05","name":"Injection"}],"CWE-798":[{"id":"A07","name":"Authentication Failures"}]}`

func noDedupFindings() []model.Finding {
	var out []model.Finding
	// The detected set, in several agents, with a repeated CWE: distinct ids
	// are what count, on both sides.
	for i, c := range []string{"CWE-22", "CWE-79", "CWE-89", "CWE-89", "CWE-259", "CWE-1234"} {
		agent := "cwe"
		if i%2 == 1 {
			agent = "xss"
		}
		out = append(out, model.Finding{AgentType: agent, Category: c})
	}
	return out
}

// The agent computes found over EVERY category whatever the audit selected,
// so the two computations agree exactly when every category is selected.
func TestRecomputeCoverageEqualsTheAgentOnNoDedupInput(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":[],`+noDedupTable+`}`)
	findings := noDedupFindings()
	applyComplianceMapping(findings, m)
	got := recomputeOwaspCoverage(json.RawMessage(agentManifestNoDedup), findings, m)
	var gotV, wantV interface{}
	if err := json.Unmarshal(got, &gotV); err != nil {
		t.Fatalf("recomputed manifest is not JSON: %v", err)
	}
	_ = json.Unmarshal([]byte(agentManifestNoDedup), &wantV)
	if !reflect.DeepEqual(gotV, wantV) {
		t.Errorf("with nothing deduped the backend must reproduce the agent's manifest\n got %s\nwant %s",
			got, agentManifestNoDedup)
	}
}

// On a subset run found(cat) is the labels actually applied (§3.3): an
// unselected category found nothing in this audit and is marked as such.
func TestRecomputeCoverageSubsetCountsAppliedLabels(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":["A07"],`+noDedupTable+`}`)
	findings := noDedupFindings()
	applyComplianceMapping(findings, m)
	var manifest struct {
		Categories []struct {
			ID         string   `json:"id"`
			FoundCWEs  []string `json:"found_cwes"`
			FoundCount int      `json:"found_count"`
			Status     string   `json:"status"`
			Selected   *bool    `json:"selected"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(recomputeOwaspCoverage(json.RawMessage(agentManifestNoDedup), findings, m), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Categories {
		wantFound, wantStatus := []string{}, "clean-or-undetected"
		if c.ID == "A07" {
			wantFound, wantStatus = []string{"CWE-259"}, "found"
		}
		if !reflect.DeepEqual(c.FoundCWEs, wantFound) || c.FoundCount != len(wantFound) || c.Status != wantStatus {
			t.Errorf("%s: found_cwes=%v found_count=%d status=%q, want %v %q", c.ID, c.FoundCWEs, c.FoundCount, c.Status, wantFound, wantStatus)
		}
		if marked := c.Selected != nil; marked != (c.ID != "A07") || (marked && *c.Selected) {
			t.Errorf("%s: selected marker = %v, want false on unselected categories only", c.ID, c.Selected)
		}
	}
}

func TestRecomputeCoverageDropsWhatDedupRemoved(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":[],`+noDedupTable+`}`)
	// CWE-259 (the only A04 row) and CWE-22 were deduped away, and an OWASP
	// copy row must never count as a finding of its own.
	findings := []model.Finding{
		{AgentType: "cwe", Category: "CWE-79"}, {AgentType: "cwe", Category: "CWE-89"},
		{AgentType: "owasp", Category: "CWE-22"},
	}
	var manifest struct {
		Categories []struct {
			ID         string   `json:"id"`
			FoundCWEs  []string `json:"found_cwes"`
			FoundCount int      `json:"found_count"`
			Status     string   `json:"status"`
		} `json:"categories"`
		Unmapped []string `json:"unmapped_cwes"`
	}
	if err := json.Unmarshal(recomputeOwaspCoverage(json.RawMessage(agentManifestNoDedup), findings, m), &manifest); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"A01": 0, "A04": 0, "A05": 2, "A07": 0}
	for _, c := range manifest.Categories {
		if c.FoundCount != want[c.ID] || len(c.FoundCWEs) != want[c.ID] {
			t.Errorf("%s: found_count=%d found_cwes=%v, want %d", c.ID, c.FoundCount, c.FoundCWEs, want[c.ID])
		}
		if (c.FoundCount == 0) != (c.Status == "clean-or-undetected") {
			t.Errorf("%s: status %q disagrees with found_count %d", c.ID, c.Status, c.FoundCount)
		}
		if c.FoundCWEs == nil {
			t.Errorf("%s: found_cwes must stay an array, not null", c.ID)
		}
	}
	// 0096 M4: unmapped is recounted from the final set too — no persisted
	// row carries CWE-1234 any more, so it is no longer reported.
	if manifest.Unmapped == nil || len(manifest.Unmapped) != 0 {
		t.Errorf("unmapped_cwes must be recounted from the final set (none): %v", manifest.Unmapped)
	}
}

func TestRecomputeCoverageNoManifestStaysNone(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2021","selected":[],`+noDedupTable+`}`)
	if got := recomputeOwaspCoverage(nil, nil, m); got != nil {
		t.Errorf("no manifest stays no manifest, got %s", got)
	}
}

func TestLabelFinalSetRejectedMappingClaimsNothingFound(t *testing.T) {
	findings := []model.Finding{{AgentType: "cwe", Category: "CWE-89"}}
	if got := labelFinalSet(findings, nil, false, json.RawMessage(agentManifestNoDedup)); string(got) != agentManifestNoDedup {
		t.Errorf("legacy mode keeps the agent's manifest verbatim, got %s", got)
	}
	got := labelFinalSet(findings, nil, true, json.RawMessage(agentManifestNoDedup))
	var manifest struct {
		Edition    string                   `json:"edition"`
		Categories []map[string]interface{} `json:"categories"`
	}
	if err := json.Unmarshal(got, &manifest); err != nil || manifest.Edition != "2025" || len(manifest.Categories) == 0 {
		t.Fatalf("a rejected mapping restates the agent's manifest, got %s (%v)", got, err)
	}
	for _, c := range manifest.Categories {
		if c["found_count"] != 0.0 || len(c["found_cwes"].([]interface{})) != 0 || c["status"] != "clean-or-undetected" {
			t.Errorf("%v: a rejected mapping labels nothing, so nothing was found: %v", c["id"], c)
		}
		if c["mapped_count"] == nil || c["name"] == nil {
			t.Errorf("%v: the agent's edition knowledge must survive: %v", c["id"], c)
		}
	}
	if findings[0].ComplianceLabels != nil {
		t.Errorf("no mapping, no labels: %+v", findings[0].ComplianceLabels)
	}
	for _, raw := range []string{`not json`, `{"edition":"2021"}`} {
		if got := labelFinalSet(nil, nil, true, json.RawMessage(raw)); got != nil {
			t.Errorf("a manifest the backend cannot restate is dropped, got %s for %q", got, raw)
		}
	}
	if got := labelFinalSet(nil, nil, true, nil); got != nil {
		t.Errorf("no manifest stays no manifest, got %s", got)
	}
}

func TestWithoutMapperFindingsOnlyInMappingMode(t *testing.T) {
	findings := func() []model.Finding {
		return []model.Finding{{AgentType: "cwe", Title: "a"}, {AgentType: "owasp", Title: "copy"}}
	}
	legacy := map[string]*model.ScanResult{"owasp": {}}
	if got := withoutMapperFindings(findings(), legacy); len(got) != 2 {
		t.Fatalf("legacy mode keeps the copy rows, got %+v", got)
	}
	mapping := map[string]*model.ScanResult{"owasp": {MappingMode: true}}
	if got := withoutMapperFindings(findings(), mapping); len(got) != 1 || got[0].AgentType != "cwe" {
		t.Fatalf("mapping mode persists no owasp row, got %+v", got)
	}
}

func TestLineageSkipReason(t *testing.T) {
	// 0096 M1: a mapper agent never owns lineage, in ANY mode — mapping,
	// legacy with copies, legacy with none, errored or rescued. The reason is
	// the §10 log line, so it is asserted verbatim.
	const mapper = "mapper agents do not own lineage (0096)"
	for agent, want := range map[string]string{"owasp": mapper, "cwe": "", "xss": "", "chaos": "", "": ""} {
		if got := lineageSkipReason(agent); got != want {
			t.Errorf("agent %q: reason %q, want %q", agent, got, want)
		}
	}
}

func TestLegacyMapperCopiesNeverReachTheLineagePass(t *testing.T) {
	var ran []string
	svc := &mockLineageService{
		recordScanOutcomeFn: func(_ *model.Audit, _ *model.Source, agentType string, _ *model.ScanResult) error {
			ran = append(ran, agentType)
			return nil
		},
	}
	for name, outcomes := range map[string]map[string]*model.ScanResult{
		"legacy result": {"owasp": {}, "cwe": {}},
		"no result":     {"cwe": {}},
	} {
		ran = nil
		findings := []model.Finding{
			{AgentType: "cwe", Fingerprint: "fp", Category: "CWE-798"},
			{AgentType: "owasp", Fingerprint: "copy", Category: "A07"},
		}
		recordLineageOutcomes(svc, &model.Audit{ID: "a"}, &model.Source{ID: "s", Path: "/p"}, findings, outcomes)
		if !reflect.DeepEqual(ran, []string{"cwe"}) {
			t.Errorf("%s: lineage passes = %v, want only cwe: legacy copies are persisted but own no lineage (0096 M1)", name, ran)
		}
	}
}

func TestMappingModeCopiesNeverReachTheLineagePass(t *testing.T) {
	// The drain empties a mapping-mode owasp result before dedup; the lineage
	// pass must hold on its own, so it is handed the copies directly here.
	var ran []string
	svc := &mockLineageService{
		recordScanOutcomeFn: func(_ *model.Audit, _ *model.Source, agentType string, _ *model.ScanResult) error {
			ran = append(ran, agentType)
			return nil
		},
	}
	outcomes := map[string]*model.ScanResult{"owasp": {MappingMode: true}, "cwe": {}}
	findings := []model.Finding{
		{AgentType: "cwe", Fingerprint: "fp", Category: "CWE-798"},
		{AgentType: "owasp", Fingerprint: "copy", Category: "A07"},
	}
	recordLineageOutcomes(svc, &model.Audit{ID: "a"}, &model.Source{ID: "s", Path: "/p"}, findings, outcomes)
	if !reflect.DeepEqual(ran, []string{"cwe"}) {
		t.Errorf("lineage passes = %v, want only cwe: a mapping-mode owasp result's rows are not sightings (0096 I1, I3)", ran)
	}
}

func TestSynthesisedResultInheritsTheRunMapping(t *testing.T) {
	m := mustMapping(t, validMapping)
	seen := map[string]*model.ScanResult{}
	svc := &mockLineageService{
		recordScanOutcomeFn: func(_ *model.Audit, _ *model.Source, agentType string, r *model.ScanResult) error {
			seen[agentType] = r
			return nil
		},
	}
	outcomes := map[string]*model.ScanResult{
		"owasp": {MappingMode: true, ComplianceMapping: m},
		"xss":   {ComplianceMapping: m},
	}
	findings := []model.Finding{{AgentType: "cwe", Fingerprint: "fp", Category: "CWE-798"}}
	recordLineageOutcomes(svc, &model.Audit{ID: "a"}, &model.Source{ID: "s", Path: "/p"}, findings, outcomes)

	if _, ran := seen["owasp"]; ran {
		t.Error("the mapping-mode owasp agent must not reach the lineage pass")
	}
	if r := seen["cwe"]; r == nil || !r.NoResultSnapshot || r.ComplianceMapping != m {
		t.Errorf("an agent rescued from deltas must still sight its rows with the run's mapping: %+v", r)
	}
	if r := seen["xss"]; r == nil || r.ComplianceMapping != m {
		t.Errorf("xss pass: %+v", r)
	}
}

// ---- 0096 review fixes (H2, M1-M4, M12, L2) ----

// H2: dedup records, on the survivor, the distinct CWE categories of the rows
// it absorbed — never its own, never an owasp copy's, never a non-CWE.
func TestDedupRecordsAbsorbedCategories(t *testing.T) {
	site := func(agent, cat string, sev model.Severity) model.Finding {
		return model.Finding{AgentType: agent, Category: cat, Severity: sev, Title: cat,
			FilePath: "db.go", LineStart: 10, Fingerprint: agent + cat}
	}
	kept, _ := dedupCrossAgentWithShadow([]model.Finding{
		site("cwe", "CWE-89", model.SeverityHigh),
		site("xss", "CWE-943", model.SeverityCritical),
		site("semgrep", "CWE-89", model.SeverityLow),
	}, "")
	if len(kept) != 1 || kept[0].Category != "CWE-943" {
		t.Fatalf("fixture must dedup to the CWE-943 row: %+v", kept)
	}
	if got, want := kept[0].AbsorbedCategories, []string{"CWE-89"}; !reflect.DeepEqual(got, want) {
		t.Errorf("absorbed = %v, want %v (canonical, distinct, own excluded)", got, want)
	}
	lone, _ := dedupCrossAgentWithShadow([]model.Finding{site("cwe", "CWE-89", model.SeverityHigh),
		{AgentType: "cwe", Category: "CWE-79", FilePath: "v.go", LineStart: 1}}, "")
	for _, f := range lone {
		if f.AbsorbedCategories != nil {
			t.Errorf("%s absorbed nothing, got %v", f.Category, f.AbsorbedCategories)
		}
	}
}

func TestApplyComplianceMappingLabelsAbsorbedCategories(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":[],`+
		`"table":{"CWE-89":[{"id":"A05","name":"Injection"}]}}`)
	findings := []model.Finding{{AgentType: "xss", Category: "CWE-943", AbsorbedCategories: []string{"CWE-89"}}}
	applyComplianceMapping(findings, m)
	want := []model.ComplianceLabel{{Framework: "owasp", Edition: "2025", CategoryID: "A05", CategoryName: "Injection", CWE: "CWE-89"}}
	if !reflect.DeepEqual(findings[0].ComplianceLabels, want) {
		t.Errorf("labels = %+v, want %+v", findings[0].ComplianceLabels, want)
	}
}

type recounted struct {
	Categories []struct {
		ID        string   `json:"id"`
		FoundCWEs []string `json:"found_cwes"`
	} `json:"categories"`
	Unmapped      []string `json:"unmapped_cwes"`
	UnmappedCount *int     `json:"unmapped_count"`
}

func decodeRecounted(t *testing.T, raw json.RawMessage) recounted {
	t.Helper()
	var r recounted
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("manifest %s: %v", raw, err)
	}
	return r
}

// H2 + M4 + M12: found and unmapped are recounted from the FINAL set,
// absorbed categories included, canonical ids throughout.
func TestRecomputeCoverageCountsAbsorbedAndUnmapped(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":[],`+noDedupTable+`}`)
	findings := []model.Finding{
		{AgentType: "xss", Category: "CWE-943", AbsorbedCategories: []string{"CWE-89"}},
		{AgentType: "cwe", Category: "CWE-079"},
		{AgentType: "cwe", Category: "CWE-01234"},
		{AgentType: "owasp", Category: "CWE-4321"},
	}
	r := decodeRecounted(t, recomputeOwaspCoverage(json.RawMessage(agentManifestNoDedup), findings, m))
	for _, c := range r.Categories {
		if c.ID == "A05" && !reflect.DeepEqual(c.FoundCWEs, []string{"CWE-79", "CWE-89"}) {
			t.Errorf("A05 found_cwes = %v, want [CWE-79 CWE-89]", c.FoundCWEs)
		}
	}
	if !reflect.DeepEqual(r.Unmapped, []string{"CWE-943", "CWE-1234"}) || r.UnmappedCount == nil || *r.UnmappedCount != 2 {
		t.Errorf("unmapped = %v (%v), want [CWE-943 CWE-1234] 2", r.Unmapped, r.UnmappedCount)
	}
}

// M4: a rejected mapping clears unmapped too — no label was applied, so no
// CWE was established as unmapped by this run's final set either.
func TestClearCoverageClearsUnmapped(t *testing.T) {
	r := decodeRecounted(t, clearOwaspCoverage(json.RawMessage(agentManifestNoDedup)))
	if r.Unmapped == nil || len(r.Unmapped) != 0 || r.UnmappedCount == nil || *r.UnmappedCount != 0 {
		t.Errorf("unmapped = %v (%v), want [] 0", r.Unmapped, r.UnmappedCount)
	}
}

// M4: a manifest the backend cannot recount against the mapping is cleared
// (edition differs) or dropped (unreadable), never persisted as sent.
func TestRecomputeCoverageClearsWhatItCannotRecount(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2021","selected":[],`+noDedupTable+`}`)
	findings := []model.Finding{{AgentType: "cwe", Category: "CWE-89"}}
	got := recomputeOwaspCoverage(json.RawMessage(agentManifestNoDedup), findings, m)
	var manifest struct {
		Edition    string                   `json:"edition"`
		Categories []map[string]interface{} `json:"categories"`
		Unmapped   []string                 `json:"unmapped_cwes"`
	}
	if err := json.Unmarshal(got, &manifest); err != nil || manifest.Edition != "2025" || len(manifest.Categories) != 4 {
		t.Fatalf("an other-edition manifest is restated, got %s (%v)", got, err)
	}
	for _, c := range manifest.Categories {
		if c["found_count"] != 0.0 || c["status"] != "clean-or-undetected" {
			t.Errorf("%v: another edition's counts cannot be vouched for: %v", c["id"], c)
		}
	}
	if len(manifest.Unmapped) != 0 {
		t.Errorf("unmapped must be cleared: %v", manifest.Unmapped)
	}
	for _, raw := range []string{`not json`, `{"edition":"2021"}`, `[]`} {
		if got := recomputeOwaspCoverage(json.RawMessage(raw), findings, m); got != nil {
			t.Errorf("unreadable manifest %q must be dropped, got %s", raw, got)
		}
	}
}

// M3: only the owasp agent's result may carry the coverage manifest.
func TestExtractOwaspCoverageOnlyFromTheOwaspSnapshot(t *testing.T) {
	snap, _ := json.Marshal(map[string]any{"findings": []any{}, "owasp_coverage": json.RawMessage(agentManifestNoDedup)})
	for _, at := range []string{"cwe", "xss", ""} {
		if got := extractOwaspCoverage(&model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: at, Snapshot: snap}); got != nil {
			t.Errorf("agent %q: a scan agent's owasp_coverage must be ignored, got %s", at, got)
		}
	}
}

// M2: once the run's owasp result answered in mapping mode, a later legacy
// owasp snapshot neither flips it back nor drops the mapping.
func TestNoteOwaspAnswerMappingModeIsSticky(t *testing.T) {
	outcomes := map[string]*model.ScanResult{}
	mappingEvt := &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: "owasp",
		Snapshot: json.RawMessage(`{"findings":[],"mapping":` + validMapping + `}`)}
	legacyEvt := &model.AgUIEvent{Type: model.EventStateSnapshot, AgentType: "owasp",
		Snapshot: json.RawMessage(`{"findings":[{"category":"A07"}]}`)}
	outcomes["owasp"] = &model.ScanResult{}
	m := noteOwaspAnswer(mappingEvt, nil, outcomes, nil)
	prev := outcomes["owasp"]
	outcomes["owasp"] = &model.ScanResult{} // the drain re-parses every snapshot
	got := noteOwaspAnswer(legacyEvt, prev, outcomes, m)
	if got != m || !outcomes["owasp"].MappingMode {
		t.Errorf("a legacy snapshot after a mapping-mode one flipped the run: mode=%v mapping kept=%v",
			outcomes["owasp"].MappingMode, got == m)
	}
}

// L2: selected is bounded.
func TestParseComplianceMappingRejectsOversizedSelection(t *testing.T) {
	sel := func(n int) string {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = `"A01"`
		}
		return strings.Join(ids, ",")
	}
	raw := func(n int) json.RawMessage {
		return json.RawMessage(`{"version":1,"framework":"owasp","edition":"2025","selected":[` + sel(n) + `],"table":{}}`)
	}
	if _, err := parseComplianceMapping(raw(101)); err == nil {
		t.Error("101 selected entries must be rejected")
	}
	if _, err := parseComplianceMapping(raw(100)); err != nil {
		t.Errorf("100 selected entries must be accepted: %v", err)
	}
}

// M12: a zero-padded table key is the canonical CWE, folded with its twin.
func TestParseComplianceMappingCanonicalisesKeys(t *testing.T) {
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":[],`+
		`"table":{"CWE-089":[{"id":"A05","name":"Injection"}],"CWE-89":[{"id":"A05","name":"Injection"},{"id":"A03","name":"X"}]}}`)
	if _, padded := m.Table["CWE-089"]; padded || len(m.Table) != 1 || len(m.Table["CWE-89"]) != 2 {
		t.Errorf("table = %+v, want one CWE-89 key with A05 and A03", m.Table)
	}
}
