//go:build e2e

package e2e

// Feature 0074 P2a/P2b: the findings API filters by provenance, server side
// (plan section 5.6 item 3; AC39, AC10).
//
// THE CONTRACT. GET /api/audits/{id}?provenance=<value> serves the persisted
// audit with only the findings <value> selects:
//
//   - an exact provenance ("skill", "llm", "llm_l5_verified", "semgrep") matches
//     that provenance literally;
//   - "llm_family" matches llm and llm_l5_verified together (P2a);
//   - "both" matches a finding whose persisted validation.provenance_origins
//     spans the skill family and the LLM family (P2b), whichever tier won the
//     dedup;
//   - no parameter serves every finding, as before 0074;
//   - an unknown value (or a different casing, e.g. LLM_FAMILY) serves no
//     findings, as an exact match on a provenance nobody has.
//
// The fixture also carries malformed provenance_origins (string, object,
// null, non-string and blank entries); every GET must still answer 200.
//
// The selection is the one the UI and the MCP tool vulture_get_findings make
// over the SAME fixture (internal/handler/testdata/provenance_filter_cases_0074.json),
// so the three surfaces cannot drift. The filter only selects: every served
// finding's validation_status, confidence and validation blob are identical
// to what the unfiltered GET serves (AC10), and a filtered GET never rewrites
// the stored findings.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

const (
	provE2EAuditID  = "audit-0074-provfilter"
	provE2ESourceID = "src-0074-provfilter"
	provE2EFixture  = "../../internal/handler/testdata/provenance_filter_cases_0074.json"
)

type provE2ECases struct {
	Findings []model.Finding     `json:"findings"`
	Expect   map[string][]string `json:"expect"`
}

func loadProvE2ECases(t *testing.T) provE2ECases {
	t.Helper()
	raw, err := os.ReadFile(provE2EFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var c provE2ECases
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return c
}

func provE2EPersisted(c provE2ECases) []model.Finding {
	out := make([]model.Finding, 0, len(c.Findings))
	for _, f := range c.Findings {
		f.ID = "id-" + f.Fingerprint
		f.AuditID = provE2EAuditID
		f.Description = "d"
		f.Recommendation = "r"
		f.LineEnd = f.LineStart
		out = append(out, f)
	}
	return out
}

// provE2ESeed persists a completed audit holding the fixture's findings,
// exactly as a finished run stores them (validation blob included).
func provE2ESeed(base *repository.SQLiteRepo, c provE2ECases) error {
	now := time.Now().UTC().Truncate(time.Second)
	if err := base.CreateSource(&model.Source{ID: provE2ESourceID, Type: model.SourceTypeLocal,
		Path: "/work/provfilter", CreatedAt: now}); err != nil {
		return err
	}
	audit := &model.Audit{ID: provE2EAuditID, SourceID: provE2ESourceID, Types: []string{"cwe", "chaos"},
		Status: model.AuditStatusCompleted, Scores: map[string]int{}, CreatedAt: now, CompletedAt: &now}
	if err := base.CreateAudit(audit); err != nil {
		return err
	}
	return base.SaveFindings(provE2EAuditID, provE2EPersisted(c))
}

// newProvE2EServer seeds the store, then starts the backend over it.
func newProvE2EServer(t *testing.T, c provE2ECases) string {
	t.Helper()
	cfg := testConfig(t)
	base, err := repository.NewSQLiteRepo(cfg.DBPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	if err := provE2ESeed(base, c); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	_ = base.Close()
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)
	return addr
}

func provE2EGet(t *testing.T, addr, value string) []model.Finding {
	t.Helper()
	path := "/api/audits/" + provE2EAuditID
	if value != "" {
		path += "?provenance=" + url.QueryEscape(value)
	}
	resp, err := httpGet(addr, path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET %s: status %d", path, resp.StatusCode)
	}
	var audit model.Audit
	readJSON(t, resp, &audit)
	return audit.Findings
}

func provE2EFingerprints(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Fingerprint)
	}
	sort.Strings(out)
	return out
}

func provE2ESorted(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func provE2EByFingerprint(findings []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		out[f.Fingerprint] = f
	}
	return out
}

func assertProvE2EValidationSame(t *testing.T, value string, got, base model.Finding) {
	t.Helper()
	same := got.ValidationStatus == base.ValidationStatus &&
		got.ValidationConfidence == base.ValidationConfidence &&
		reflect.DeepEqual(got.Validation, base.Validation)
	if !same {
		t.Fatalf("provenance=%s served %s with validation (%q, %v, %v); unfiltered serves (%q, %v, %v)",
			value, got.Fingerprint, got.ValidationStatus, got.ValidationConfidence, got.Validation,
			base.ValidationStatus, base.ValidationConfidence, base.Validation)
	}
}

// assertProvE2EFilterKeepsValidation requires the filter to serve its rows
// (an empty answer would satisfy AC10 vacuously), each with the validation
// the unfiltered GET serves.
func assertProvE2EFilterKeepsValidation(t *testing.T, addr, value string, want int, base map[string]model.Finding) {
	t.Helper()
	served := provE2EGet(t, addr, value)
	if len(served) != want {
		t.Fatalf("provenance=%s served %d rows, want %d", value, len(served), want)
	}
	for _, f := range served {
		assertProvE2EValidationSame(t, value, f, base[f.Fingerprint])
	}
}

// AC39: over persisted findings, each filter value selects exactly the rows
// the shared fixture lists, the same rows the UI and MCP select.
func TestProvenanceFilter0074_APISelectsTheSharedFixtureRows(t *testing.T) {
	c := loadProvE2ECases(t)
	addr := newProvE2EServer(t, c)
	for value, want := range c.Expect {
		got := provE2EFingerprints(provE2EGet(t, addr, value))
		if !reflect.DeepEqual(got, provE2ESorted(want)) {
			t.Errorf("provenance=%s served %v, want %v", value, got, provE2ESorted(want))
		}
	}
}

// AC39 (P2a): llm_family equals llm ∪ llm_l5_verified (plan T0.0, T2.1).
func TestProvenanceFilter0074_LLMFamilyEqualsUnionOfLLMAndL5Verified(t *testing.T) {
	c := loadProvE2ECases(t)
	addr := newProvE2EServer(t, c)
	union := append(provE2EFingerprints(provE2EGet(t, addr, "llm")),
		provE2EFingerprints(provE2EGet(t, addr, "llm_l5_verified"))...)
	got := provE2EFingerprints(provE2EGet(t, addr, "llm_family"))
	if len(got) == 0 || !reflect.DeepEqual(got, provE2ESorted(union)) {
		t.Fatalf("llm_family served %v, want the non-empty union llm ∪ llm_l5_verified = %v", got, provE2ESorted(union))
	}
}

// AC39 (P2b): both is read from the PERSISTED validation.provenance_origins,
// so a merged row is found whichever tier won, and a row whose origins stay
// in one family (semgrep + skill, llm + llm_l5_verified) is not. Origins are
// normalised (trim, lower-case), so [" Skill ", "LLM"] is both; empty, blank,
// null, string, object and non-string origins are not, and none of them may
// turn the GET into an error (provE2EGet requires 200).
func TestProvenanceFilter0074_BothReadsPersistedOrigins(t *testing.T) {
	c := loadProvE2ECases(t)
	addr := newProvE2EServer(t, c)
	got := provE2EFingerprints(provE2EGet(t, addr, "both"))
	want := []string{"fp-0074-both-llm-wins", "fp-0074-both-skill-wins", "fp-0074-origins-case"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("both served %v, want %v", got, want)
	}
}

// AC10: a filter never changes a row's validation_status, confidence or blob,
// and never rewrites what is stored: the unfiltered GET after every filtered
// GET still serves every row unchanged.
func TestProvenanceFilter0074_FilterNeverChangesValidationStatus(t *testing.T) {
	c := loadProvE2ECases(t)
	addr := newProvE2EServer(t, c)
	before := provE2EGet(t, addr, "")
	base := provE2EByFingerprint(before)
	for value, want := range c.Expect {
		assertProvE2EFilterKeepsValidation(t, addr, value, len(want), base)
	}
	if after := provE2EGet(t, addr, ""); !reflect.DeepEqual(after, before) {
		t.Fatalf("unfiltered GET changed after filtered reads:\nbefore %+v\nafter  %+v", before, after)
	}
}

// Regression pin (passes before 0074): without the parameter the API serves
// every persisted finding, the legacy row with no provenance included.
func TestProvenanceFilter0074_NoParameterServesEveryFinding(t *testing.T) {
	c := loadProvE2ECases(t)
	addr := newProvE2EServer(t, c)
	got := provE2EFingerprints(provE2EGet(t, addr, ""))
	want := provE2EFingerprints(c.Findings)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unfiltered GET served %v, want %v", got, want)
	}
}
