//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
)

// Feature 0096 I3 / I4: a mapping-mode OWASP result carries zero findings BY
// DESIGN — the labels ride on the CWE rows — so its silence about an OWASP
// lineage row is not evidence of repair. The backend advertises
// `accepts_mapping`, and from that moment an OWASP result carrying a `mapping`
// object must never reach the closure pass, whatever the mapping contains and
// whether or not this backend can yet apply it. Without that, advertising the
// capability is exactly the skew the negotiation exists to prevent: the agent
// answers in mapping mode and every OWASP lineage row is marked fixed.
//
// 0096 M1 extends this to every mode: a mapper agent never owns lineage. So
// the OWASP row here is one a pre-0096 backend left behind (seeded), and the
// third scan — a LEGACY result carrying a different copy, which under 0063
// closed that row — must leave it untouched too and create no row for its
// copy: OWASP lineage is switched off, in any mode.

// scriptedAgent answers the i-th /run request with results[i] (the last one
// repeats) and returns a minimal agent_start/result/agent_end stream.
type scriptedAgent struct {
	mu      sync.Mutex
	results []string
	calls   int
	srv     *httptest.Server
}

func newScriptedAgent(t *testing.T, results ...string) *scriptedAgent {
	t.Helper()
	a := &scriptedAgent{results: results}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/run") {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f, _ := w.(http.Flusher)
		for _, frame := range []string{
			"event: agent_start\ndata: {\"run_id\":\"r\"}\n\n",
			"event: result\ndata: " + a.next() + "\n\n",
			"event: agent_end\ndata: {}\n\n",
		} {
			_, _ = fmt.Fprint(w, frame)
			if f != nil {
				f.Flush()
			}
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *scriptedAgent) next() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := a.calls
	if i >= len(a.results) {
		i = len(a.results) - 1
	}
	a.calls++
	return a.results[i]
}

const (
	mappingCWEResult = `{"findings":[{"severity":"high","category":"CWE-798",` +
		`"title":"Hardcoded credential","description":"d","file_path":"main.go",` +
		`"line_start":1,"line_end":1,"recommendation":"r","provenance":"skill",` +
		`"check_id":"cwe.secret"}],"summary":"cwe","score":70}`
	// A legacy 0063 OWASP copy row, on its own file so cross-agent dedup
	// cannot fold it into the CWE row above.
	legacyOwaspCopy = `{"findings":[{"severity":"high","category":"A07",` +
		`"title":"A07 Authentication Failures: hardcoded credential","description":"d",` +
		`"file_path":"auth.go","line_start":4,"line_end":4,"recommendation":"r",` +
		`"provenance":"skill","check_id":"owasp.A07.cwe_798"}],"summary":"owasp","score":80}`
	legacyOwaspEmpty = `{"findings":[],"summary":"owasp","score":100}`
	// A legacy result whose only copy is a different finding than
	// legacyOwaspCopy's: the A07 copy's absence from it is a legacy closure.
	legacyOwaspOtherCopy = `{"findings":[{"severity":"high","category":"A05",` +
		`"title":"A05 Injection: SQL injection","description":"d",` +
		`"file_path":"query.go","line_start":9,"line_end":9,"recommendation":"r",` +
		`"provenance":"skill","check_id":"owasp.A05.cwe_89"}],"summary":"owasp","score":80}`
)

// lineageAPIRow is the subset of a lineage row this test reads off the API.
type lineageAPIRow struct {
	ID            string `json:"id"`
	AgentType     string `json:"agent_type"`
	CurrentStatus string `json:"current_status"`
	LatestAuditID string `json:"latest_audit_id"`
}

// lineageRowsOf lists every lineage row for the source through the real HTTP
// API, over both the literal and the symlink-resolved path forms.
func lineageRowsOf(t *testing.T, addr, dir string) map[string]lineageAPIRow {
	t.Helper()
	out := map[string]lineageAPIRow{}
	paths := []string{dir}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
		paths = append(paths, resolved)
	}
	for _, p := range paths {
		resp, err := httpGet(addr, "/api/lineage?limit=500&source_path="+p)
		if err != nil {
			t.Fatalf("GET /api/lineage: %v", err)
		}
		var rows []lineageAPIRow
		readJSON(t, resp, &rows)
		for _, r := range rows {
			out[r.ID] = r
		}
	}
	return out
}

func rowOfAgent(rows map[string]lineageAPIRow, agent string) (lineageAPIRow, int) {
	var found lineageAPIRow
	n := 0
	for _, r := range rows {
		if r.AgentType == agent {
			found, n = r, n+1
		}
	}
	return found, n
}

// waitForLineage polls until cond holds over the source's rows, or fails.
func waitForLineage(t *testing.T, addr, dir, what string, cond func(map[string]lineageAPIRow) bool) map[string]lineageAPIRow {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var rows map[string]lineageAPIRow
	for time.Now().Before(deadline) {
		if rows = lineageRowsOf(t, addr, dir); cond(rows) {
			return rows
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; rows=%+v", what, rows)
	return nil
}

// lineageDetail reads one row by id. The by-id read is used for status because
// the default listing returns ACTIVE rows only, so a closed row would simply
// vanish from it rather than show `fixed`.
func lineageDetail(t *testing.T, addr, id string) (status string, events []string) {
	t.Helper()
	resp, err := httpGet(addr, "/api/lineage/"+id)
	if err != nil {
		t.Fatalf("GET /api/lineage/%s: %v", id, err)
	}
	var detail struct {
		Lineage lineageAPIRow `json:"lineage"`
		Events  []struct {
			EventType string `json:"event_type"`
			AuditID   string `json:"audit_id"`
		} `json:"events"`
	}
	readJSON(t, resp, &detail)
	for _, e := range detail.Events {
		events = append(events, e.EventType+"@"+e.AuditID)
	}
	return detail.Lineage.CurrentStatus, events
}

// runLineageAudit starts one cwe+owasp audit on the source and waits for it.
func runLineageAudit(t *testing.T, addr, sourceID string) string {
	t.Helper()
	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID, "types": []string{"cwe", "owasp"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	var created map[string]interface{}
	readJSON(t, resp, &created)
	auditID, _ := created["id"].(string)
	if auditID == "" {
		t.Fatalf("no audit id in %v", created)
	}
	if final := pollAuditStatus(t, addr, auditID, 15*time.Second); final["status"] != "completed" {
		t.Fatalf("audit %s ended %q, want completed", auditID, final["status"])
	}
	return auditID
}

func TestMappingModeOwaspResultClosesNoLineage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mapping string
	}{
		{"a well-formed v1 mapping", `{"version":1,"framework":"owasp","edition":"2025",` +
			`"selected":[],"table":{"CWE-798":[{"id":"A07","name":"Authentication Failures"}]}}`},
		{"an empty table", `{"version":1,"framework":"owasp","edition":"2025","selected":[],"table":{}}`},
		// A mapping this backend cannot read is still a mapping-mode answer:
		// its zero findings are by design, so they prove nothing (I3).
		{"a mapping version this backend does not speak", `{"version":99,"framework":"owasp","table":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mappingResult := `{"findings":[],"summary":"owasp","score":83,"mapping":` + tc.mapping + `}`
			cwe := newScriptedAgent(t, mappingCWEResult)
			owasp := newScriptedAgent(t, legacyOwaspCopy, mappingResult, legacyOwaspOtherCopy)

			cfg := testConfig(t)
			cfg.Agents["cwe"] = config.AgentConfig{Name: "CWE", Type: "cwe", URL: cwe.srv.URL}
			cfg.Agents["owasp"] = config.AgentConfig{Name: "OWASP", Type: "owasp", URL: owasp.srv.URL}
			addr, cleanup := startTestServer(t, cfg)
			defer cleanup()

			dir := createTestSourceDir(t)
			resp, err := httpPost(addr, "/api/sources", map[string]string{"type": "local", "path": dir})
			if err != nil {
				t.Fatalf("POST /api/sources: %v", err)
			}
			var src map[string]interface{}
			readJSON(t, resp, &src)
			sourceID, _ := src["id"].(string)

			// Scan 1 (legacy OWASP agent): its copy owns no lineage (M1); the
			// cwe row does, and is cloned into the row a pre-0096 backend
			// would have left for the copy.
			runLineageAudit(t, addr, sourceID)
			rows := waitForLineage(t, addr, dir, "the first scan's cwe row", func(r map[string]lineageAPIRow) bool {
				_, nOwasp := rowOfAgent(r, "owasp")
				_, nCWE := rowOfAgent(r, "cwe")
				return nOwasp == 0 && nCWE == 1
			})
			cweRow, _ := rowOfAgent(rows, "cwe")
			seededID := seedOwaspLineageRow(t, cfg.DBPath, cweRow.ID)
			rows = waitForLineage(t, addr, dir, "the seeded owasp row", func(r map[string]lineageAPIRow) bool {
				row, n := rowOfAgent(r, "owasp")
				return n == 1 && row.ID == seededID
			})
			owaspRow, _ := rowOfAgent(rows, "owasp")
			if owaspRow.CurrentStatus != "open" {
				t.Fatalf("owasp row after scan 1 = %q, want open", owaspRow.CurrentStatus)
			}
			_, before := lineageDetail(t, addr, owaspRow.ID)

			// Scan 2 (mapping mode). The cwe pass re-sighting its row is the
			// sync point that this audit's lineage goroutine ran; the owasp
			// pass shares the goroutine, and the grace window after it
			// catches a closure made in either order.
			second := runLineageAudit(t, addr, sourceID)
			waitForLineage(t, addr, dir, "the second scan's cwe re-sighting", func(r map[string]lineageAPIRow) bool {
				row, n := rowOfAgent(r, "cwe")
				return n == 1 && row.LatestAuditID == second
			})
			for end := time.Now().Add(750 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
				if status, _ := lineageDetail(t, addr, owaspRow.ID); status != "open" {
					t.Fatalf("a mapping-mode OWASP result (%s) closed lineage row %s: status %q, want open. "+
						"Its zero findings are by design, not evidence of repair (0096 I3)",
						tc.name, owaspRow.ID, status)
				}
			}
			if _, after := lineageDetail(t, addr, owaspRow.ID); len(after) != len(before) {
				t.Fatalf("a mapping-mode OWASP result must record NO lineage event on an OWASP row: "+
					"before scan %s %v, after %v", second, before, after)
			}

			// Scan 3 (legacy agent, another copy): under 0063 this closed the
			// row. A mapper owns no lineage (M1): no transition, no new row.
			third := runLineageAudit(t, addr, sourceID)
			waitForLineage(t, addr, dir, "the third scan's cwe re-sighting", func(r map[string]lineageAPIRow) bool {
				row, n := rowOfAgent(r, "cwe")
				return n == 1 && row.LatestAuditID == third
			})
			time.Sleep(750 * time.Millisecond)
			status, final := lineageDetail(t, addr, owaspRow.ID)
			if status != "open" || len(final) != len(before) {
				t.Fatalf("a LEGACY OWASP result touched pre-0096 row %s: status %q, events before %v, after %v "+
					"(0096 M1: mapper agents do not own lineage)", owaspRow.ID, status, before, final)
			}
			if _, n := rowOfAgent(lineageRowsOf(t, addr, dir), "owasp"); n != 1 {
				t.Fatalf("a legacy copy created an owasp lineage row: %d owasp rows, want only the seeded one", n)
			}
		})
	}
}
