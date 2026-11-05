//go:build e2e

package e2e

// Feature 0074 P4 — E2E business contract (AC17, AC18, AC19, AC31).
//
// One agent reports the SAME weakness at the SAME site twice: once from its
// deterministic skill tier, once from its LLM tier (the commonest both-tier
// pair, plan R23). Through the real backend — dispatch, stream drain, the
// cross-agent merge, persistence, GET — the audit must persist exactly ONE
// row, and that row must still say both tiers found it
// (validation.provenance_origins) and keep the LLM tier's reasoning
// (validation.merged_descriptions). The run must also account for the
// collapsed LLM row in one `dedup_buckets` log line, with nothing lost.
//
// Today the pair collapses into the skill row and the LLM row's provenance
// and reasoning vanish without a trace.

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// e2eLogSink is a concurrency-safe log destination: the run's goroutines log
// while the test reads.
type e2eLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *e2eLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *e2eLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

const llmReasoning0074 = "uid is read from request.args and concatenated into the SELECT without a bound parameter"

// bothTierResult is one agent's result: a skill row and an LLM row for one
// site at equal severity, plus the agent-side dedup counters (it emitted 2
// LLM rows and collapsed 1 itself before sending).
func bothTierResult(t *testing.T) string {
	t.Helper()
	row := func(prov, checkID, title, desc string) map[string]interface{} {
		return map[string]interface{}{
			"severity": "high", "category": "CWE-89", "title": title, "description": desc,
			"file_path": "src/db.py", "line_start": 42, "line_end": 42,
			"recommendation": "use a parameterised query", "provenance": prov, "check_id": checkID,
		}
	}
	b, err := json.Marshal(map[string]interface{}{
		"findings": []interface{}{
			row("skill", "cwe.sql_injection.string_concat", "SQL injection (string-built query)", "Pattern match: string-built SQL"),
			row("llm", "", "Unparameterised SQL query", llmReasoning0074),
		},
		"summary": "cwe", "score": 60, "result_schema": 2,
		"llm_emitted": 2, "llm_collapsed_agent": 1,
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(b)
}

func validationStrings(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal validation value: %v", err)
	}
	return string(b)
}

func assertProvenanceOriginsBothTiers(t *testing.T, f model.Finding) {
	t.Helper()
	var origins []string
	raw, ok := f.Validation["provenance_origins"]
	if ok {
		_ = json.Unmarshal([]byte(validationStrings(t, raw)), &origins)
	}
	if !containsString(origins, "skill") || !containsString(origins, "llm") {
		t.Errorf("persisted validation.provenance_origins = %v, want it to name both skill and llm (AC17); validation=%v",
			origins, f.Validation)
	}
}

func assertReasoningKept(t *testing.T, f model.Finding) {
	t.Helper()
	if md := validationStrings(t, f.Validation["merged_descriptions"]); !strings.Contains(md, llmReasoning0074) {
		t.Errorf("the LLM tier's reasoning did not survive the merge (AC18): merged_descriptions=%s", md)
	}
}

// bucketLineFor returns the dedup_buckets log line for (audit, agent), or "".
func bucketLineFor(logs, auditID, agent string) string {
	for _, line := range strings.Split(logs, "\n") {
		if isDedupBucketLine(line, auditID, agent) {
			return line
		}
	}
	return ""
}

func isDedupBucketLine(line, auditID, agent string) bool {
	return strings.Contains(line, "dedup_buckets") &&
		strings.Contains(line, "audit_id="+auditID) &&
		strings.Contains(line, "agent="+agent)
}

func TestSkillAndLLMRowForOneSitePersistAsOneRowNamingBothTiers_0074(t *testing.T) {
	sink := &e2eLogSink{}
	log.SetOutput(sink)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	cwe := newScriptedAgent(t, bothTierResult(t))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe})
	a := h.run(t, []string{"cwe"}, nil)

	if len(a.Findings) != 1 {
		t.Fatalf("persisted %d findings, want ONE merged row for one weakness at one site; findings=%+v", len(a.Findings), a.Findings)
	}
	survivor := a.Findings[0]
	assertProvenanceOriginsBothTiers(t, survivor)
	// #15: the merge record is served under ?detail=full only.
	assertNoMergeDetail(t, survivor)
	assertReasoningKept(t, detailFullFindings(t, h.addr, a.ID)[0])

	assertBucketTokens(t, sink.String(), a.ID, "cwe",
		"emitted=2", "collapsed_agent=1", "collapsed_go=1", "unique=0", "lost=0")
}

// assertBucketTokens requires the (audit, agent) dedup_buckets line to carry
// every wanted key=value token exactly.
func assertBucketTokens(t *testing.T, logs, auditID, agent string, want ...string) {
	t.Helper()
	line := bucketLineFor(logs, auditID, agent)
	if line == "" {
		t.Fatalf("no dedup_buckets log line for audit=%s agent=%s (AC19)", auditID, agent)
	}
	tokens := strings.Fields(line)
	for _, w := range want {
		if !containsString(tokens, w) {
			t.Errorf("dedup_buckets line lacks %q: %s", w, line)
		}
	}
}

// detailFullFindings GETs the audit with ?detail=full, which serves the merge
// record (validation.merged_descriptions) the default response leaves out.
func detailFullFindings(t *testing.T, addr, auditID string) []model.Finding {
	t.Helper()
	resp, err := httpGet(addr, "/api/audits/"+auditID+"?detail=full")
	if err != nil {
		t.Fatalf("GET audit ?detail=full: %v", err)
	}
	var a labelsAudit
	readJSON(t, resp, &a)
	if len(a.Findings) == 0 {
		t.Fatalf("GET ?detail=full served no findings")
	}
	return a.Findings
}

// assertNoMergeDetail: the default GET leaves the merge record out (#15).
func assertNoMergeDetail(t *testing.T, f model.Finding) {
	t.Helper()
	if _, ok := f.Validation["merged_descriptions"]; ok {
		t.Errorf("default GET served validation.merged_descriptions; it belongs to ?detail=full only: %v", f.Validation)
	}
}

// agentCollapsedResult is the same weakness as bothTierResult AFTER the
// agent's own skill/LLM dedup (contract C3): ONE skill row that carries the
// dropped LLM row in merged_llm.
func agentCollapsedResult(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"findings": []interface{}{map[string]interface{}{
			"severity": "high", "category": "CWE-89", "title": "SQL injection (string-built query)",
			"description": "Pattern match: string-built SQL", "file_path": "src/db.py", "line_start": 42, "line_end": 42,
			"recommendation": "use a parameterised query", "provenance": "skill", "check_id": "cwe.sql_injection.string_concat",
			"merged_llm": []interface{}{map[string]interface{}{"provenance": "llm", "description": llmReasoning0074}},
		}},
		"summary": "cwe", "score": 60, "result_schema": 2,
		"llm_emitted": 1, "llm_collapsed_agent": 1,
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(b)
}

// C3 end to end: a pair the AGENT collapsed reaches the backend as one row
// carrying merged_llm, and the persisted row still names both tiers and keeps
// the LLM reasoning; merged_llm itself is never persisted or served.
func TestAgentCollapsedPairPersistsBothTiers_0074(t *testing.T) {
	cwe := newScriptedAgent(t, agentCollapsedResult(t))
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe})
	a := h.run(t, []string{"cwe"}, nil)
	if len(a.Findings) != 1 {
		t.Fatalf("persisted %d findings, want 1; findings=%+v", len(a.Findings), a.Findings)
	}
	assertProvenanceOriginsBothTiers(t, a.Findings[0])
	full := detailFullFindings(t, h.addr, a.ID)[0]
	assertReasoningKept(t, full)
	if len(full.MergedLLM) != 0 || len(a.Findings[0].MergedLLM) != 0 {
		t.Errorf("merged_llm was persisted/served: %+v", full.MergedLLM)
	}
	resp, err := httpGet(h.addr, "/api/audits/"+a.ID+"?provenance=both")
	if err != nil {
		t.Fatalf("GET ?provenance=both: %v", err)
	}
	var both map[string]interface{}
	readJSON(t, resp, &both)
	if fs, _ := both["findings"].([]interface{}); len(fs) != 1 || both["origins_recorded"] != true {
		t.Errorf("provenance=both must select the agent-collapsed row with origins_recorded=true; got %d rows, origins_recorded=%v",
			len(fs), both["origins_recorded"])
	}
}
