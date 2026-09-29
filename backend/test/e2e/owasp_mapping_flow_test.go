//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
)

// Feature 0096: the backend stream path driven by the OWASP result the REAL
// agent emits in mapping mode, not a hand-written approximation of it.
//
// The fixture agents/owasp/tests/fixtures/owasp_0096_mapping_stream.json is the
// OWASP agent's byte-for-byte SSE output for one request, captured together
// with that request's config and priors and the CWE result they were derived
// from. The OWASP agent's own suite re-runs the agent on the same inputs and
// fails when its output drifts from the file, so this test always exercises
// the payload the agent actually sends.
//
// Here a mock CWE agent returns the fixture's CWE findings; the backend taps
// them and forwards them to a mock OWASP agent, which checks that the request
// is the one the fixture was captured for and then replays the captured
// stream verbatim. The persisted audit must then hold no OWASP rows, labelled
// CWE rows, the OWASP score and the coverage manifest.

// owaspFlowFixture is the captured agent exchange.
type owaspFlowFixture struct {
	RunID  string                 `json:"run_id"`
	Config map[string]interface{} `json:"config"`
	// AcceptsMapping is the top-level /run capability field (0096 §2.1, H1):
	// out of band, never inside Config.
	AcceptsMapping json.RawMessage          `json:"accepts_mapping"`
	CWEFindings    []map[string]interface{} `json:"cwe_findings"`
	Priors         []map[string]interface{} `json:"priors"`
	Stream         string                   `json:"stream"`
}

func loadOwaspFlowFixture(t *testing.T) owaspFlowFixture {
	t.Helper()
	p := filepath.Join("..", "..", "..",
		"agents", "owasp", "tests", "fixtures", "owasp_0096_mapping_stream.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read the captured OWASP agent exchange %s: %v", p, err)
	}
	var fx owaspFlowFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode %s: %v", p, err)
	}
	if fx.Stream == "" || len(fx.CWEFindings) == 0 {
		t.Fatalf("fixture %s has no stream or no CWE findings", p)
	}
	return fx
}

// streamFrame is one `event:`/`data:` pair of the captured SSE stream.
type streamFrame struct {
	Event string
	Data  json.RawMessage
}

func parseCapturedStream(t *testing.T, stream string) []streamFrame {
	t.Helper()
	var out []streamFrame
	sc := bufio.NewScanner(strings.NewReader(stream))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	var cur streamFrame
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			cur = streamFrame{Event: strings.TrimPrefix(line, "event: ")}
		case strings.HasPrefix(line, "data: "):
			cur.Data = json.RawMessage(strings.TrimPrefix(line, "data: "))
			out = append(out, cur)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan captured stream: %v", err)
	}
	return out
}

// capturedOwaspResult is the subset of the captured result event the
// assertions derive their expectations from.
type capturedOwaspResult struct {
	Findings []json.RawMessage `json:"findings"`
	Score    float64           `json:"score"`
	Mapping  *struct {
		Version   int                                   `json:"version"`
		Framework string                                `json:"framework"`
		Edition   string                                `json:"edition"`
		Selected  []string                              `json:"selected"`
		Table     map[string][]model.ComplianceCategory `json:"table"`
	} `json:"mapping"`
	OwaspCoverage flowCoverageManifest `json:"owasp_coverage"`
}

type flowCoverageCategory struct {
	ID          string   `json:"id"`
	MappedCount int      `json:"mapped_count"`
	FoundCWEs   []string `json:"found_cwes"`
	FoundCount  int      `json:"found_count"`
	Status      string   `json:"status"`
	Selected    *bool    `json:"selected"`
}

type flowCoverageManifest struct {
	Edition        string                 `json:"edition"`
	CWEStageStatus string                 `json:"cwe_stage_status"`
	Categories     []flowCoverageCategory `json:"categories"`
}

// capturedResult returns the fixture's result event and asserts the fixture
// is a mapping-mode exchange at all (no finding events, a mapping object).
func capturedResult(t *testing.T, frames []streamFrame) capturedOwaspResult {
	t.Helper()
	var res *capturedOwaspResult
	for _, f := range frames {
		switch f.Event {
		case "finding":
			t.Fatalf("the captured OWASP stream emits a finding event; a mapping-mode answer emits none (0096 I1): %s", f.Data)
		case "result":
			res = &capturedOwaspResult{}
			if err := json.Unmarshal(f.Data, res); err != nil {
				t.Fatalf("decode captured result: %v", err)
			}
		}
	}
	switch {
	case res == nil:
		t.Fatalf("the captured OWASP stream has no result event")
	case res.Mapping == nil:
		t.Fatalf("the captured OWASP result carries no mapping object: the agent did not answer accepts_mapping=1 in mapping mode")
	case len(res.Findings) != 0:
		t.Fatalf("the captured OWASP result carries %d findings, want 0", len(res.Findings))
	}
	return *res
}

// replayRunBody is the part of one OWASP /run body the replay agent keeps.
type replayRunBody struct {
	Config         map[string]interface{}   `json:"config"`
	PriorFindings  []map[string]interface{} `json:"prior_findings"`
	AcceptsMapping json.RawMessage          `json:"accepts_mapping"`
}

// replayOwaspAgent records the one /run request it gets and answers it with
// the captured stream, verbatim.
type replayOwaspAgent struct {
	mu       sync.Mutex
	requests []replayRunBody
	srv      *httptest.Server
}

func newReplayOwaspAgent(t *testing.T, stream string) *replayOwaspAgent {
	t.Helper()
	a := &replayOwaspAgent{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(200)
			return
		}
		var body replayRunBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.mu.Lock()
		a.requests = append(a.requests, body)
		a.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, stream)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// assertCapturedRequest checks the backend asked the OWASP agent exactly what
// the fixture was captured for, so replaying the captured answer is faithful.
func (a *replayOwaspAgent) assertCapturedRequest(t *testing.T, fx owaspFlowFixture) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.requests) != 1 {
		t.Fatalf("owasp agent received %d /run requests, want 1", len(a.requests))
	}
	req := a.requests[0]
	if !reflect.DeepEqual(normaliseJSON(t, req.Config), normaliseJSON(t, fx.Config)) {
		t.Fatalf("owasp request config = %v, the fixture was captured for %v", req.Config, fx.Config)
	}
	if len(fx.AcceptsMapping) == 0 || string(req.AcceptsMapping) != string(fx.AcceptsMapping) {
		t.Fatalf("owasp /run top-level accepts_mapping = %s, the fixture was captured for %s",
			req.AcceptsMapping, fx.AcceptsMapping)
	}
	if len(req.PriorFindings) != len(fx.Priors) {
		t.Fatalf("owasp request carried %d priors, the fixture was captured with %d", len(req.PriorFindings), len(fx.Priors))
	}
	for i, want := range fx.Priors {
		got := normaliseJSON(t, req.PriorFindings[i]).(map[string]interface{})
		for k, v := range normaliseJSON(t, want).(map[string]interface{}) {
			if !reflect.DeepEqual(got[k], v) {
				t.Errorf("prior %d field %s = %#v, the fixture was captured with %#v", i, k, got[k], v)
			}
		}
	}
}

// normaliseJSON round-trips v so numbers compare as JSON numbers.
func normaliseJSON(t *testing.T, v interface{}) interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestOwaspMappingFlowWithRealAgentPayload(t *testing.T) {
	fx := loadOwaspFlowFixture(t)
	captured := capturedResult(t, parseCapturedStream(t, fx.Stream))
	m := captured.Mapping

	cweResult, err := json.Marshal(map[string]interface{}{
		"findings": fx.CWEFindings, "summary": "cwe", "score": 70,
	})
	if err != nil {
		t.Fatalf("marshal cwe result: %v", err)
	}
	cwe := newScriptedAgent(t, string(cweResult))
	owasp := newReplayOwaspAgent(t, fx.Stream)

	cfg := testConfig(t)
	cfg.Agents["cwe"] = config.AgentConfig{Name: "CWE", Type: "cwe", URL: cwe.srv.URL}
	cfg.Agents["owasp"] = config.AgentConfig{Name: "OWASP", Type: "owasp", URL: owasp.srv.URL}
	addr, cleanup := startTestServer(t, cfg)
	t.Cleanup(cleanup)
	dir := createTestSourceDir(t)
	resp, err := httpPost(addr, "/api/sources", map[string]string{"type": "local", "path": dir})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]interface{}
	readJSON(t, resp, &src)
	sourceID, _ := src["id"].(string)
	if sourceID == "" {
		t.Fatalf("no source id in %v", src)
	}
	h := &labelsHarness{addr: addr, dir: dir, sourceID: sourceID}

	// The user's OWASP config is the fixture's, minus the backend-owned key.
	// (accepts_mapping is not a config key at all: it is out of band.)
	userCfg := map[string]interface{}{}
	for k, v := range fx.Config {
		if k != "cwe_stage_status" {
			userCfg[k] = v
		}
	}
	a := h.run(t, []string{"cwe", "owasp"}, map[string]interface{}{"owasp": userCfg})

	owasp.assertCapturedRequest(t, fx)

	// I1: zero OWASP rows; every CWE finding persisted exactly once.
	assertNoOwaspRows(t, a)
	if len(a.Findings) != len(fx.CWEFindings) {
		t.Fatalf("persisted %d findings, want the %d CWE rows; findings=%+v", len(a.Findings), len(fx.CWEFindings), a.Findings)
	}

	// Labels: the agent's table narrowed to its `selected`, per category.
	labelled := 0
	for _, raw := range fx.CWEFindings {
		category, _ := raw["category"].(string)
		f := findingByCategory(t, a, category)
		if f.AgentType != "cwe" {
			t.Errorf("finding %s persisted as agent_type=%q, want cwe", category, f.AgentType)
		}
		var want []model.ComplianceLabel
		for _, c := range m.Table[category] {
			if len(m.Selected) == 0 || containsString(m.Selected, c.ID) {
				want = append(want, model.ComplianceLabel{Framework: m.Framework, Edition: m.Edition,
					CategoryID: c.ID, CategoryName: c.Name, CWE: category})
			}
		}
		if !reflect.DeepEqual(f.ComplianceLabels, want) {
			t.Errorf("finding %s: compliance_labels = %+v, want %+v", category, f.ComplianceLabels, want)
		}
		if len(want) > 0 {
			labelled++
		}
	}
	// Non-vacuous: the fixture's selected categories do label something, and
	// its mapped-but-unselected and unmapped CWEs do not.
	if labelled == 0 || labelled == len(fx.CWEFindings) {
		t.Fatalf("fixture labels %d of %d findings; it must exercise both labelled and unlabelled rows", labelled, len(fx.CWEFindings))
	}

	// The OWASP agent's score is recorded as it sent it.
	if got, ok := a.Scores["owasp"]; !ok || got != int(captured.Score) {
		t.Errorf("scores.owasp = %d (present=%v), want the agent's %d; scores=%v", got, ok, int(captured.Score), a.Scores)
	}

	assertPersistedCoverage(t, a, captured)
	assertFlowLineage(t, h, fx, m.Edition, m.Table)
}

// assertPersistedCoverage checks the manifest was persisted, recounted from
// the labelled rows: a selected category found exactly the CWEs whose rows
// carry its label; an unselected one found nothing and says it was not
// selected. The agent's own mapped_count and cwe_stage_status survive.
func assertPersistedCoverage(t *testing.T, a labelsAudit, captured capturedOwaspResult) {
	t.Helper()
	if len(a.OwaspCoverage) == 0 || string(a.OwaspCoverage) == "null" {
		t.Fatalf("audit %s persisted no owasp_coverage", a.ID)
	}
	var got flowCoverageManifest
	if err := json.Unmarshal(a.OwaspCoverage, &got); err != nil {
		t.Fatalf("decode persisted owasp_coverage: %v", err)
	}
	sent := captured.OwaspCoverage
	if got.Edition != sent.Edition || got.CWEStageStatus != sent.CWEStageStatus {
		t.Errorf("coverage edition/status = %s/%s, the agent sent %s/%s", got.Edition, got.CWEStageStatus, sent.Edition, sent.CWEStageStatus)
	}
	if len(got.Categories) != len(sent.Categories) || len(got.Categories) != 10 {
		t.Fatalf("coverage has %d categories, the agent sent %d (want 10)", len(got.Categories), len(sent.Categories))
	}
	labelledCWEs := map[string]map[string]bool{}
	for _, f := range a.Findings {
		for _, l := range f.ComplianceLabels {
			if labelledCWEs[l.CategoryID] == nil {
				labelledCWEs[l.CategoryID] = map[string]bool{}
			}
			labelledCWEs[l.CategoryID][l.CWE] = true
		}
	}
	for i, c := range got.Categories {
		if c.ID != sent.Categories[i].ID || c.MappedCount != sent.Categories[i].MappedCount {
			t.Errorf("coverage category %d = %s/%d mapped, the agent sent %s/%d", i, c.ID, c.MappedCount, sent.Categories[i].ID, sent.Categories[i].MappedCount)
		}
		selected := len(captured.Mapping.Selected) == 0 || containsString(captured.Mapping.Selected, c.ID)
		if selected == (c.Selected != nil && !*c.Selected) {
			t.Errorf("coverage %s: selected marker %v, want selected=%v", c.ID, c.Selected, selected)
		}
		if c.FoundCount != len(labelledCWEs[c.ID]) || len(c.FoundCWEs) != c.FoundCount {
			t.Errorf("coverage %s: found_count=%d found_cwes=%v, but %d distinct CWEs carry its label",
				c.ID, c.FoundCount, c.FoundCWEs, len(labelledCWEs[c.ID]))
		}
		for _, cwe := range c.FoundCWEs {
			if !labelledCWEs[c.ID][cwe] {
				t.Errorf("coverage %s reports %s found, but no persisted row carries that label", c.ID, cwe)
			}
		}
	}
}

// assertFlowLineage checks the run created no OWASP lineage and that each
// mapped CWE row's lineage carries the FULL table's categories, selected or not.
func assertFlowLineage(t *testing.T, h *labelsHarness, fx owaspFlowFixture, edition string, table map[string][]model.ComplianceCategory) {
	t.Helper()
	rows := h.waitLineage(t, "one cwe lineage row per CWE finding", func(r []labelledLineageRow) bool {
		return len(rowsOfAgent(r, "cwe")) == len(fx.CWEFindings)
	})
	if n := len(rowsOfAgent(rows, "owasp")); n != 0 {
		t.Errorf("a mapping-mode run created %d owasp lineage row(s), want 0", n)
	}
	key := model.ComplianceFrameworkOWASP + ":" + edition
	for _, raw := range fx.CWEFindings {
		category, _ := raw["category"].(string)
		cats := table[category]
		if len(cats) == 0 {
			continue
		}
		row, ok := rowByCategory(rows, "cwe", category)
		if !ok {
			t.Fatalf("no cwe lineage row for %s; rows=%+v", category, rows)
		}
		want := make([]string, 0, len(cats))
		for _, c := range cats {
			want = append(want, c.ID)
		}
		if got := row.ComplianceLabels[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("lineage %s: compliance_labels[%s] = %v, want the full table %v", category, key, got, want)
		}
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
