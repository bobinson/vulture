package handler

// Feature 0074 P2a/P2b, server-side provenance filter on the findings API
// (plan section 5.6 item 3; AC39, AC10).
//
// GET /api/audits/{id}?provenance=<value> returns the audit with only the
// findings the value selects. The vocabulary is the one the UI and the MCP
// tool vulture_get_findings use, and all three consume the SAME fixture,
// testdata/provenance_filter_cases_0074.json, so they select the same rows:
//
//   - an exact provenance value ("skill", "llm", "llm_l5_verified",
//     "semgrep", ...) matches that provenance literally;
//   - "llm_family" matches llm and llm_l5_verified together;
//   - "both" matches rows whose validation.provenance_origins spans the skill
//     family and the LLM family;
//   - no parameter returns every finding, as today.
//
// The filter only selects rows. It never changes a row's validation_status,
// validation_confidence or validation blob (AC10), nor any audit-level field
// of the response (scores, owasp_coverage, status, types).
//
// LAYER. The mock service below returns every finding whatever the query, so
// these tests pin the filter in the HANDLER (AuditHandler.Get), the layer that
// already reads the request and enriches the audit before writing it. The
// e2e test (test/e2e/provenance_filter_0074_test.go) pins the same contract
// end to end, whatever layer implements it.
//
// ROBUSTNESS. The fixture carries malformed provenance_origins values (a
// string, an object, null, non-string entries, empty tiers). Every request
// must still answer 200 with the other rows: a malformed value is "not both",
// never a 500 for the whole audit. An unknown value (or a different casing of
// a vocabulary word) selects nothing, as the 0058 exact-match filter does.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const provFilterFixture0074 = "testdata/provenance_filter_cases_0074.json"

type provFilterCases0074 struct {
	Findings []model.Finding     `json:"findings"`
	Expect   map[string][]string `json:"expect"`
}

func loadProvFilterCases0074(t *testing.T) provFilterCases0074 {
	t.Helper()
	raw, err := os.ReadFile(provFilterFixture0074)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var c provFilterCases0074
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return c
}

// serveProv0074 serves GET /api/audits/a-0074[?provenance=v] from a mock
// service holding the fixture's findings and audit-level aggregates, and
// returns the response body. Any status other than 200 fails the test.
func serveProv0074(t *testing.T, c provFilterCases0074, value string) []byte {
	t.Helper()
	svc := &mockAuditService{getFn: func(id string) (*model.Audit, error) {
		findings := append([]model.Finding(nil), c.Findings...)
		return &model.Audit{ID: id, SourceID: "src-0074", Types: []string{"cwe", "chaos"},
			Status: model.AuditStatusCompleted, Findings: findings, FindingsCount: len(findings),
			Scores:        map[string]int{"cwe": 61, "chaos": 80},
			OwaspCoverage: json.RawMessage(`{"edition":"2025","categories":[{"id":"A05","found":2}]}`)}, nil
	}}
	target := "/api/audits/a-0074"
	if value != "" {
		target += "?provenance=" + url.QueryEscape(value)
	}
	w := httptest.NewRecorder()
	NewAuditHandler(svc).Get(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", target, w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

func getProvFiltered0074(t *testing.T, c provFilterCases0074, value string) []model.Finding {
	t.Helper()
	var audit model.Audit
	if err := json.Unmarshal(serveProv0074(t, c, value), &audit); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	return audit.Findings
}

func provFingerprints0074(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Fingerprint)
	}
	sort.Strings(out)
	return out
}

func sortedCopy0074(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// AC39: every filter value selects exactly the rows the shared fixture lists.
func TestAuditGetProvenanceFilter0074_SelectsFixtureRows(t *testing.T) {
	c := loadProvFilterCases0074(t)
	for value, want := range c.Expect {
		t.Run(value, func(t *testing.T) {
			got := provFingerprints0074(getProvFiltered0074(t, c, value))
			if !reflect.DeepEqual(got, sortedCopy0074(want)) {
				t.Fatalf("provenance=%s selected %v, want %v", value, got, sortedCopy0074(want))
			}
		})
	}
}

// AC39 (P2a): llm_family is exactly the union of the llm and llm_l5_verified
// selections, never more (no skill/semgrep/legacy row) and never less.
func TestAuditGetProvenanceFilter0074_LLMFamilyIsUnionOfMembers(t *testing.T) {
	c := loadProvFilterCases0074(t)
	union := append(provFingerprints0074(getProvFiltered0074(t, c, "llm")),
		provFingerprints0074(getProvFiltered0074(t, c, "llm_l5_verified"))...)
	got := provFingerprints0074(getProvFiltered0074(t, c, "llm_family"))
	if !reflect.DeepEqual(got, sortedCopy0074(union)) {
		t.Fatalf("llm_family selected %v, want llm ∪ llm_l5_verified = %v", got, sortedCopy0074(union))
	}
}

// AC39 (P2b): both is derived from validation.provenance_origins, not from
// the surviving row's own provenance. A row whose origins are all skill-family
// (semgrep + skill) or all LLM-family is not "both"; a row with no validation
// blob (a pre-0074 row) is never "both". Origins are normalised (trim,
// lower-case) like isLLMProvenance, so [" Skill ", "LLM"] is "both"; an empty
// or blank origin is not a tier, so ["", "llm"] is not.
func TestAuditGetProvenanceFilter0074_BothFollowsOriginsNotWinner(t *testing.T) {
	c := loadProvFilterCases0074(t)
	got := provFingerprints0074(getProvFiltered0074(t, c, "both"))
	want := []string{"fp-0074-both-llm-wins", "fp-0074-both-skill-wins", "fp-0074-origins-case"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("both selected %v, want %v (two merges and the normalised-case row only)", got, want)
	}
}

// AC39 robustness: malformed, empty or same-family provenance_origins values
// are "not both" and never fail the request. Pinned by name so a regression
// reads as the edge case it is, not as a count mismatch.
func TestAuditGetProvenanceFilter0074_MalformedOriginsAreNotBoth(t *testing.T) {
	c := loadProvFilterCases0074(t)
	both := provByFingerprint0074(getProvFiltered0074(t, c, "both"))
	if len(both) == 0 {
		t.Fatalf("both selected nothing; the per-row check below would be vacuous")
	}
	for _, fp := range []string{"fp-0074-origins-empty-tier", "fp-0074-origins-blank-tier",
		"fp-0074-origins-llm-pair", "fp-0074-origins-string", "fp-0074-origins-null",
		"fp-0074-origins-object", "fp-0074-origins-absent", "fp-0074-origins-nonstring", "fp-0074-legacy"} {
		if _, ok := both[fp]; ok {
			t.Errorf("both selected %s; its provenance_origins does not span both families", fp)
		}
	}
}

// audit-level fields of a GET response, everything except the findings list
// and its count (whether findings_count reports the filtered size is not part
// of this contract).
func provAuditFields0074(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	delete(m, "findings")
	delete(m, "findings_count")
	return m
}

// AC10 (audit level): the filter selects rows only. Scores, owasp_coverage,
// status and every other audit-level field are byte-identical to the
// unfiltered GET, for every vocabulary value, unknown ones included.
func TestAuditGetProvenanceFilter0074_AuditFieldsUnchanged(t *testing.T) {
	c := loadProvFilterCases0074(t)
	base := provAuditFields0074(t, serveProv0074(t, c, ""))
	for value, want := range c.Expect {
		if got := provFingerprints0074(getProvFiltered0074(t, c, value)); len(got) != len(want) {
			t.Fatalf("provenance=%s returned %v; the filter is not applied, so this check would be vacuous", value, got)
		}
		if got := provAuditFields0074(t, serveProv0074(t, c, value)); !reflect.DeepEqual(got, base) {
			t.Fatalf("provenance=%s changed audit-level fields:\n got %v\nwant %v", value, got, base)
		}
	}
}

// Regression pin (passes before 0074): no provenance parameter still returns
// every finding, including a legacy row with no provenance at all.
func TestAuditGetProvenanceFilter0074_AbsentReturnsEveryRow(t *testing.T) {
	c := loadProvFilterCases0074(t)
	got := provFingerprints0074(getProvFiltered0074(t, c, ""))
	if len(got) != len(c.Findings) {
		t.Fatalf("unfiltered GET returned %d findings, want %d", len(got), len(c.Findings))
	}
}

func provByFingerprint0074(findings []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		out[f.Fingerprint] = f
	}
	return out
}

func assertValidationUnchanged0074(t *testing.T, value string, got model.Finding, base model.Finding) {
	t.Helper()
	same := got.ValidationStatus == base.ValidationStatus &&
		got.ValidationConfidence == base.ValidationConfidence &&
		reflect.DeepEqual(got.Validation, base.Validation)
	if !same {
		t.Fatalf("provenance=%s changed %s's validation: got (%q, %v, %v), unfiltered (%q, %v, %v)", value,
			got.Fingerprint, got.ValidationStatus, got.ValidationConfidence, got.Validation,
			base.ValidationStatus, base.ValidationConfidence, base.Validation)
	}
}

// AC10: a row's validation_status (and the rest of its validation) is
// identical whether or not it is reached through a provenance filter. The
// check runs only over rows the filter returned, so it also requires the
// filter to return something (an empty answer would satisfy AC10 vacuously).
func TestAuditGetProvenanceFilter0074_NeverChangesValidationStatus(t *testing.T) {
	c := loadProvFilterCases0074(t)
	base := provByFingerprint0074(getProvFiltered0074(t, c, ""))
	for value, want := range c.Expect {
		filtered := getProvFiltered0074(t, c, value)
		if len(filtered) != len(want) {
			t.Fatalf("provenance=%s returned %d rows, want %d", value, len(filtered), len(want))
		}
		for _, f := range filtered {
			assertValidationUnchanged0074(t, value, f, base[f.Fingerprint])
		}
	}
}
