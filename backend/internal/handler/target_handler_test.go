package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 P4 — the handler's own two jobs: cutting the target key out of
// the path, and turning a query string into a normalised filter. The endpoint
// behaviour itself is pinned by the E2E contract suite; these cover the parsing
// edges a live fixture never produces.

func TestParseTargetPathKeepsAGitKeyWhole(t *testing.T) {
	gitKey := "git:github.com/acme/proj"
	for _, tc := range []struct {
		name       string
		path       string
		wantKey    string
		wantAction string
	}{
		{"marker key", "/api/targets/marker:abc123/aggregate", "marker:abc123", "aggregate"},
		{"scans", "/api/targets/marker:abc123/scans", "marker:abc123", "scans"},
		{
			// The case the escaped path exists for: encodeURIComponent turns
			// the remote's slashes into %2F, and splitting the DECODED path
			// would cut the key at github.com.
			"escaped git key", "/api/targets/" + url.PathEscape(gitKey) + "/aggregate", gitKey, "aggregate",
		},
		{"unescaped git key", "/api/targets/git:github.com/acme/proj/aggregate", gitKey, "aggregate"},
		{"no action", "/api/targets/marker:abc123", "marker:abc123", ""},
		{"not a target path", "/api/lineage/abc", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, action := parseTargetPath(tc.path)
			if key != tc.wantKey || action != tc.wantAction {
				t.Fatalf("parseTargetPath(%q) = (%q, %q), want (%q, %q)",
					tc.path, key, action, tc.wantKey, tc.wantAction)
			}
		})
	}
}

func TestParseAggregateQueryDefaultsAndClamps(t *testing.T) {
	q := parseAggregateQuery("k", url.Values{})
	if q.Page != 1 || q.PageSize != defaultAggregatePageSize {
		t.Fatalf("empty query = page %d size %d, want 1 / %d", q.Page, q.PageSize, defaultAggregatePageSize)
	}
	if q.IncludeTerminal {
		t.Fatal("the default view is `active`; an omitted status must not include the terminal states")
	}
	if q.Tier != "" || q.MinSeen != 0 || len(q.Severities) != 0 || len(q.Scans) != 0 {
		t.Fatalf("an empty query must set no filter at all: %+v", q)
	}

	values := url.Values{
		"scans":     {"a, b ,,c"},
		"status":    {"ALL"},
		"tier":      {"LLM"},
		"min_seen":  {"3"},
		"severity":  {"Critical,HIGH"},
		"page":      {"0"},
		"page_size": {"100000"},
	}
	q = parseAggregateQuery("k", values)
	if len(q.Scans) != 3 {
		t.Fatalf("scans = %v, want the blanks dropped and three ids kept", q.Scans)
	}
	if !q.IncludeTerminal {
		t.Fatal("status=ALL is status=all; the parameter is not case-sensitive")
	}
	if q.Tier != model.TierLLM {
		t.Fatalf("tier = %q, want %q", q.Tier, model.TierLLM)
	}
	if len(q.Severities) != 2 || q.Severities[0] != "critical" || q.Severities[1] != "high" {
		t.Fatalf("severities = %v, want them lower-cased for the SQL comparison", q.Severities)
	}
	if q.Page != 1 {
		t.Fatalf("page=0 must clamp to 1, got %d — a deep link is user-editable and a 500 there "+
			"is worse than the first page", q.Page)
	}
	if q.PageSize != maxAggregatePageSize {
		t.Fatalf("page_size = %d, want the %d cap", q.PageSize, maxAggregatePageSize)
	}
	if q.Offset() != 0 {
		t.Fatalf("page 1 offset = %d, want 0", q.Offset())
	}
}

func TestParseAggregateQueryRejectsAnUnknownTier(t *testing.T) {
	// "both" is not a tier; it is the ABSENCE of the filter. Accepting it as a
	// value would produce a WHERE clause matching nothing.
	q := parseAggregateQuery("k", url.Values{"tier": {"both"}})
	if q.Tier != "" {
		t.Fatalf("tier = %q for an unknown value, want the filter unset", q.Tier)
	}
}

// stubTargetService records what reached the service and answers fixed data.
type stubTargetService struct {
	gotQuery model.AggregateQuery
	targets  []model.TargetSummary
	scans    []model.TargetScan
}

func (s *stubTargetService) ListTargets() ([]model.TargetSummary, error) { return s.targets, nil }
func (s *stubTargetService) Scans(string) ([]model.TargetScan, error)    { return s.scans, nil }
func (s *stubTargetService) Aggregate(q model.AggregateQuery) (*model.AggregateReport, error) {
	s.gotQuery = q
	return &model.AggregateReport{Page: q.Page, PageSize: q.PageSize, Rows: []model.AggregateRow{}}, nil
}

func TestTargetHandlerRoutes(t *testing.T) {
	svc := &stubTargetService{
		targets: []model.TargetSummary{{TargetKey: "marker:abc", DisplayName: "proj"}},
		scans:   []model.TargetScan{{AuditID: "a1", Types: []string{"cwe"}}},
	}
	h := NewTargetHandler(svc)

	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest(http.MethodGet, "/api/targets", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/targets = %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.Route(w, httptest.NewRequest(http.MethodGet, "/api/targets/marker:abc/scans", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET .../scans = %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.Route(w, httptest.NewRequest(http.MethodGet, "/api/targets/marker:abc/aggregate?tier=det&page=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET .../aggregate = %d", w.Code)
	}
	if svc.gotQuery.TargetKey != "marker:abc" || svc.gotQuery.Tier != model.TierDeterministic || svc.gotQuery.Page != 2 {
		t.Fatalf("the parsed query did not reach the service: %+v", svc.gotQuery)
	}
	var report model.AggregateReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("aggregate body: %v", err)
	}
	if report.Rows == nil {
		t.Fatal("`rows` must serialise as [] and never null; the table iterates it")
	}

	w = httptest.NewRecorder()
	h.Route(w, httptest.NewRequest(http.MethodGet, "/api/targets/marker:abc/nonsense", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("an unknown sub-resource = %d, want 404", w.Code)
	}

	// The endpoints are reads. A write verb is refused before anything is
	// parsed, so a viewer instance cannot be probed with one.
	w = httptest.NewRecorder()
	h.Route(w, httptest.NewRequest(http.MethodPost, "/api/targets/marker:abc/aggregate", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST .../aggregate = %d, want 405", w.Code)
	}
}
