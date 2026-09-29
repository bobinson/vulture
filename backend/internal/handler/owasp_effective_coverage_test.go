package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// 0096 follow-up at the unit level: the effective coverage manifest served at
// read time. The business contract — triage through the real API, the store
// left untouched — is pinned in test/e2e/owasp_coverage_false_positive_0096_test.go;
// these pin the rule's edges one at a time.

type effCategory struct {
	ID                 string   `json:"id"`
	FoundCWEs          []string `json:"found_cwes"`
	FoundCount         int      `json:"found_count"`
	Status             string   `json:"status"`
	Selected           *bool    `json:"selected"`
	FalsePositiveCount *int     `json:"false_positive_count"`
}

type effManifest struct {
	Categories    []effCategory `json:"categories"`
	UnmappedCWEs  []string      `json:"unmapped_cwes"`
	UnmappedCount int           `json:"unmapped_count"`
}

func decodeEffective(t *testing.T, raw json.RawMessage) (effManifest, map[string]effCategory) {
	t.Helper()
	var m effManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("effective manifest %s: %v", raw, err)
	}
	byID := map[string]effCategory{}
	for _, c := range m.Categories {
		byID[c.ID] = c
	}
	return m, byID
}

func assertEffCategory(t *testing.T, c effCategory, found []string, fp int) {
	t.Helper()
	status := "clean-or-undetected"
	if len(found) > 0 {
		status = "found"
	}
	if !reflect.DeepEqual(c.FoundCWEs, found) || c.FoundCount != len(found) || c.Status != status {
		t.Errorf("%s: found_cwes=%v found_count=%d status=%q, want %v %q", c.ID, c.FoundCWEs, c.FoundCount, c.Status, found, status)
	}
	if c.FalsePositiveCount == nil || *c.FalsePositiveCount != fp {
		t.Errorf("%s: false_positive_count=%v, want %d", c.ID, c.FalsePositiveCount, fp)
	}
}

// recountedFixture is a mapping-mode audit exactly as the persist path leaves
// it: findings labelled by applyComplianceMapping and the manifest recounted
// by recomputeOwaspCoverage from the same set.
func recountedFixture(t *testing.T, selected string, findings []model.Finding) ([]model.Finding, json.RawMessage) {
	t.Helper()
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":`+selected+`,`+noDedupTable+`}`)
	applyComplianceMapping(findings, m)
	return findings, recomputeOwaspCoverage(json.RawMessage(agentManifestNoDedup), findings, m)
}

func withoutFalsePositiveCounts(t *testing.T, raw json.RawMessage) interface{} {
	t.Helper()
	var v map[string]interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("manifest %s: %v", raw, err)
	}
	for _, c := range v["categories"].([]interface{}) {
		delete(c.(map[string]interface{}), "false_positive_count")
	}
	return v
}

// With nothing triaged the effective manifest IS the scan-time recount, plus
// false_positive_count 0 on every category: the read-time rule and the
// persist-time rule are one rule.
func TestEffectiveCoverageWithNothingTriagedEqualsTheRecount(t *testing.T) {
	for _, selected := range []string{`[]`, `["A05","A07"]`} {
		findings, persisted := recountedFixture(t, selected, noDedupFindings())
		got := effectiveOwaspCoverage(persisted, findings, make([]bool, len(findings)))
		if !reflect.DeepEqual(withoutFalsePositiveCounts(t, got), withoutFalsePositiveCounts(t, persisted)) {
			t.Errorf("selected=%s: effective manifest differs from the recount\n got %s\nwant %s", selected, got, persisted)
		}
		_, byID := decodeEffective(t, got)
		for id, c := range byID {
			if c.FalsePositiveCount == nil || *c.FalsePositiveCount != 0 {
				t.Errorf("selected=%s: %s false_positive_count=%v, want 0", selected, id, c.FalsePositiveCount)
			}
		}
	}
}

// A category's found CWEs drop only when every finding carrying that CWE's
// label is triaged; false_positive_count counts distinct triaged findings.
func TestEffectiveCoverageExcludesTriagedFindings(t *testing.T) {
	findings, persisted := recountedFixture(t, `[]`, []model.Finding{
		{AgentType: "cwe", Category: "CWE-798"},
		{AgentType: "xss", Category: "CWE-798"},
		{AgentType: "cwe", Category: "CWE-259"}, // labels A04 and A07
		{AgentType: "cwe", Category: "CWE-89"},
	})
	_, byID := decodeEffective(t, effectiveOwaspCoverage(persisted, findings, []bool{true, false, false, false}))
	assertEffCategory(t, byID["A07"], []string{"CWE-259", "CWE-798"}, 1)

	_, byID = decodeEffective(t, effectiveOwaspCoverage(persisted, findings, []bool{true, true, true, false}))
	assertEffCategory(t, byID["A07"], []string{}, 3)
	assertEffCategory(t, byID["A04"], []string{}, 1)
	assertEffCategory(t, byID["A05"], []string{"CWE-89"}, 0)
	assertEffCategory(t, byID["A01"], []string{}, 0)
}

// A dedup survivor carries the labels of the rows it absorbed (H2): its
// triage withdraws every CWE its labels name, and it counts once per category
// however many of its labels name that category.
func TestEffectiveCoverageFollowsTheSurvivorsLabels(t *testing.T) {
	findings, persisted := recountedFixture(t, `[]`, []model.Finding{
		{AgentType: "xss", Category: "CWE-79", AbsorbedCategories: []string{"CWE-89", "CWE-798"}},
	})
	findings[0].AbsorbedCategories = nil // not persisted: the read path never has it
	_, byID := decodeEffective(t, effectiveOwaspCoverage(persisted, findings, []bool{true}))
	assertEffCategory(t, byID["A05"], []string{}, 1)
	assertEffCategory(t, byID["A07"], []string{}, 1)
}

// Only this manifest's framework and edition count; another edition's label
// on the same finding speaks for other category ids.
func TestEffectiveCoverageReadsOnlyTheManifestsEdition(t *testing.T) {
	findings, persisted := recountedFixture(t, `[]`, []model.Finding{{AgentType: "cwe", Category: "CWE-798"}})
	findings[0].ComplianceLabels = append(findings[0].ComplianceLabels,
		model.ComplianceLabel{Framework: "owasp", Edition: "2021", CategoryID: "A05", CategoryName: "x", CWE: "CWE-798"},
		model.ComplianceLabel{Framework: "asvs", Edition: "2025", CategoryID: "A05", CategoryName: "x", CWE: "CWE-798"})
	_, byID := decodeEffective(t, effectiveOwaspCoverage(persisted, findings, []bool{true}))
	assertEffCategory(t, byID["A05"], []string{}, 0)
	assertEffCategory(t, byID["A07"], []string{}, 1)
}

// An unmapped CWE is withdrawn when every finding categorised with it is
// triaged — and never on vacuous truth: a CWE only an absorbed row carried
// (no persisted finding is categorised with it) stays, as does one whose only
// rows are an OWASP agent's.
func TestEffectiveCoveragePrunesUnmappedOnlyWhenEveryFindingIsTriaged(t *testing.T) {
	findings, persisted := recountedFixture(t, `[]`, []model.Finding{
		{AgentType: "cwe", Category: "CWE-01234"},
		{AgentType: "xss", Category: "CWE-1234"},
		{AgentType: "cwe", Category: "CWE-89", AbsorbedCategories: []string{"CWE-943"}},
		{AgentType: "cwe", Category: "CWE-5555"},
	})
	findings[2].AbsorbedCategories = nil
	persistedM, _ := decodeEffective(t, persisted)
	if !reflect.DeepEqual(persistedM.UnmappedCWEs, []string{"CWE-943", "CWE-1234", "CWE-5555"}) {
		t.Fatalf("precondition: recounted unmapped = %v", persistedM.UnmappedCWEs)
	}
	cases := []struct {
		triaged []bool
		want    []string
	}{
		{[]bool{true, false, false, false}, []string{"CWE-943", "CWE-1234", "CWE-5555"}},
		{[]bool{true, true, false, false}, []string{"CWE-943", "CWE-5555"}},
		{[]bool{true, true, true, true}, []string{"CWE-943"}},
	}
	for _, c := range cases {
		m, _ := decodeEffective(t, effectiveOwaspCoverage(persisted, findings, c.triaged))
		if !reflect.DeepEqual(m.UnmappedCWEs, c.want) || m.UnmappedCount != len(c.want) {
			t.Errorf("triaged %v: unmapped = %v (%d), want %v", c.triaged, m.UnmappedCWEs, m.UnmappedCount, c.want)
		}
	}
}

// legacyNothingMapped is a pre-0096 OWASP agent's manifest for a run that
// mapped nothing — no category found, one CWE it could not place — as its SSE
// frame carried it (Python json.dumps: default separators, its own key order).
// A legacy run like it has no copy rows and no labels.
const legacyNothingMapped = `{"edition": "2025", "cwe_stage_status": "completed", "categories": [` +
	`{"id": "A07", "name": "Authentication Failures", "mapped_count": 2, "found_cwes": [], "found_count": 0, ` +
	`"status": "clean-or-undetected", "source_url": "u7"}], "unmapped_cwes": ["CWE-1234"], "unmapped_count": 1}`

// A mapping-mode run whose findings carry no label found nothing anywhere:
// none of its CWEs maps (the persist-time recount), or its mapping was
// rejected (the manifest cleared). Both manifests are the persist path's own,
// so it is still adjusted: its unmapped claims follow triage and
// false_positive_count is present.
func TestEffectiveCoverageAdjustsAnUnlabelledMappingModeAudit(t *testing.T) {
	findings := []model.Finding{{AgentType: "cwe", Category: "CWE-1234"}}
	m := mustMapping(t, `{"version":1,"framework":"owasp","edition":"2025","selected":[],`+noDedupTable+`}`)
	applyComplianceMapping(findings, m)
	if len(findings[0].ComplianceLabels) != 0 {
		t.Fatalf("precondition: CWE-1234 must map to nothing, got %+v", findings[0].ComplianceLabels)
	}
	recounted := recomputeOwaspCoverage(json.RawMessage(legacyNothingMapped), findings, m)

	eff, byID := decodeEffective(t, effectiveOwaspCoverage(recounted, findings, []bool{true}))
	assertEffCategory(t, byID["A07"], []string{}, 0)
	if len(eff.UnmappedCWEs) != 0 || eff.UnmappedCount != 0 {
		t.Errorf("recounted: unmapped = %v (%d), want none", eff.UnmappedCWEs, eff.UnmappedCount)
	}

	cleared := clearOwaspCoverage(json.RawMessage(agentManifestNoDedup))
	_, byID = decodeEffective(t, effectiveOwaspCoverage(cleared, findings, []bool{false}))
	assertEffCategory(t, byID["A07"], []string{}, 0)
}

// What is not a mapping-mode label recount is served byte for byte.
func TestEffectiveCoverageLeavesWhatItCannotRecountUntouched(t *testing.T) {
	legacy := json.RawMessage(`{"edition":"2025","cwe_stage_status":"completed","categories":[{"id":"A07",` +
		`"found_cwes":["CWE-798"],"found_count":1,"status":"found"}],"unmapped_cwes":[],"unmapped_count":0}`)
	cwe := model.Finding{AgentType: "cwe", Category: "CWE-798"}
	copyRow := model.Finding{AgentType: "owasp", Category: "A07"}
	cases := []struct {
		name     string
		raw      json.RawMessage
		findings []model.Finding
	}{
		{"no manifest", nil, []model.Finding{cwe}},
		{"null manifest", json.RawMessage(`null`), []model.Finding{cwe}},
		{"unreadable manifest", json.RawMessage(`{"categories":7}`), []model.Finding{cwe}},
		{"manifest without an edition", json.RawMessage(`{"categories":[]}`), []model.Finding{cwe}},
		{"pre-0096: owasp copy rows, no labels", legacy, []model.Finding{cwe, copyRow}},
		// A pre-0096 subset run with no copies still claims CWEs the agent
		// counted over unselected categories; no label backs them.
		{"pre-0096: no copies, found claims, no labels", legacy, []model.Finding{cwe}},
		// A pre-0096 run that mapped nothing has no copies AND no found
		// claims; only the agent's own encoding tells it from a recount.
		{"pre-0096: no copies, nothing found, unmapped claims", json.RawMessage(legacyNothingMapped),
			[]model.Finding{{AgentType: "cwe", Category: "CWE-1234"}}},
		{"pre-0096: the same manifest compacted", compactJSON(t, legacyNothingMapped),
			[]model.Finding{{AgentType: "cwe", Category: "CWE-1234"}}},
	}
	for _, c := range cases {
		triaged := make([]bool, len(c.findings))
		for i := range triaged {
			triaged[i] = true
		}
		if got := effectiveOwaspCoverage(c.raw, c.findings, triaged); string(got) != string(c.raw) {
			t.Errorf("%s: got %s, want the input unchanged", c.name, got)
		}
	}
}

func compactJSON(t *testing.T, raw string) json.RawMessage {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(raw)); err != nil {
		t.Fatalf("compact %s: %v", raw, err)
	}
	return b.Bytes()
}

// The read path: a lineage failure serves the persisted manifest, and an
// audit whose manifest cannot be adjusted costs no lineage read at all.
func TestWithEffectiveOwaspCoverage(t *testing.T) {
	findings, persisted := recountedFixture(t, `[]`, []model.Finding{{AgentType: "cwe", Category: "CWE-798", Fingerprint: "fp-1"}})
	calls := 0
	lister := &repository.MockLineageRepository{ListByAuditFn: func(string) ([]model.FindingLineage, error) {
		calls++
		return nil, errors.New("lineage store unavailable")
	}}
	audit := &model.Audit{ID: "a1", Findings: findings, OwaspCoverage: persisted}
	withEffectiveOwaspCoverage(audit, lister)
	if string(audit.OwaspCoverage) != string(persisted) || calls != 1 {
		t.Errorf("lineage failure: coverage %s (calls=%d), want the persisted manifest after one read", audit.OwaspCoverage, calls)
	}

	lister.ListByAuditFn = func(string) ([]model.FindingLineage, error) {
		calls++
		return []model.FindingLineage{{ID: "l1", AgentType: "cwe", Fingerprint: "fp-1",
			CurrentStatus: model.LineageStatusFalsePositive}}, nil
	}
	withEffectiveOwaspCoverage(audit, lister)
	if _, byID := decodeEffective(t, audit.OwaspCoverage); byID["A07"].FoundCount != 0 {
		t.Errorf("triaged finding still counted: %s", audit.OwaspCoverage)
	}

	calls = 0
	legacy := &model.Audit{ID: "a2", Findings: []model.Finding{{AgentType: "owasp", Category: "A07"}},
		OwaspCoverage: json.RawMessage(`{"edition":"2025","categories":[{"id":"A07","found_cwes":["CWE-798"]}]}`)}
	withEffectiveOwaspCoverage(legacy, lister)
	withEffectiveOwaspCoverage(&model.Audit{ID: "a3"}, lister)
	withEffectiveOwaspCoverage(audit, nil)
	withEffectiveOwaspCoverage(nil, lister)
	if calls != 0 {
		t.Errorf("an audit with nothing to adjust made %d lineage read(s)", calls)
	}
}

// The recount is only as good as the findings it is given. GetAudit swallows a
// findings-read error (nil findings, or the rows read before rows.Err), so a
// finding set that does not back every found claim of the persisted manifest
// is not the set that manifest was recounted from: findings are never
// rewritten after persist, so with nothing lost every claim is backed. Such a
// manifest is served byte for byte — never recounted into "clean", whatever
// the triage.
func TestEffectiveCoverageServesThePersistedManifestWhenTheFindingsDoNotBackIt(t *testing.T) {
	findings, persisted := recountedFixture(t, `[]`, []model.Finding{
		{AgentType: "cwe", Category: "CWE-798"},
		{AgentType: "cwe", Category: "CWE-259"}, // A04 and A07
		{AgentType: "cwe", Category: "CWE-89"},
	})
	cases := []struct {
		name     string
		findings []model.Finding
	}{
		{"findings did not load", nil},
		{"findings loaded empty", []model.Finding{}},
		{"only CWE-259's finding lost", []model.Finding{findings[0], findings[2]}},
		{"only CWE-89's finding lost", findings[:2]},
	}
	for _, c := range cases {
		for _, fp := range []bool{false, true} {
			triaged := make([]bool, len(c.findings))
			for i := range triaged {
				triaged[i] = fp
			}
			if got := effectiveOwaspCoverage(persisted, c.findings, triaged); string(got) != string(persisted) {
				t.Errorf("%s (triaged=%v): got %s, want the persisted manifest", c.name, fp, got)
			}
		}
	}
}

// The read path costs no lineage read for an audit whose findings do not back
// its manifest, and serves the persisted manifest.
func TestWithEffectiveOwaspCoverageWhenFindingsDidNotLoad(t *testing.T) {
	_, persisted := recountedFixture(t, `[]`, []model.Finding{{AgentType: "cwe", Category: "CWE-798", Fingerprint: "fp-1"}})
	calls := 0
	lister := &repository.MockLineageRepository{ListByAuditFn: func(string) ([]model.FindingLineage, error) {
		calls++
		return nil, nil
	}}
	audit := &model.Audit{ID: "a1", OwaspCoverage: persisted}
	withEffectiveOwaspCoverage(audit, lister)
	if string(audit.OwaspCoverage) != string(persisted) || calls != 0 {
		t.Errorf("findings not loaded: coverage %s (lineage reads=%d), want the persisted manifest and no read", audit.OwaspCoverage, calls)
	}
}
