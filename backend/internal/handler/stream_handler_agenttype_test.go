package handler

// RED-phase tests for feature 0050 AC 13 (BLOCKER #2):
//   AgentType proxy hardening — unconditional overwrite.
//
// Today, stream_handler.go has two near-identical guards:
//
//   line ~420 (parseSnapshot):
//     if f.AgentType == "" { f.AgentType = agentType }
//
//   line ~789 (extractDeltaFindings):
//     if f.AgentType == "" { f.AgentType = agentType }
//
// A container plugin can spoof another plugin's identity by emitting
// a non-empty `agent_type` in its SSE payload. The 0050 LLD requires
// these guards become UNCONDITIONAL: the AgentType that the proxy
// dispatched to MUST always win, irrespective of payload contents.
//
// SEAM (documented per agent brief): we test the two package-private
// helpers directly — `parseSnapshot` and `extractDeltaFindings`. Both
// take `agentType string` as an explicit parameter, take a *[]Finding
// to populate, and are already covered by sibling tests in
// stream_handler_test.go (see TestParseSnapshot). Testing through the
// HTTP layer would require spinning up real audit + stream services
// and mocking SSE end-to-end; the helpers are a much cleaner seam
// and exercise the exact lines (420-421 and 789-790) that the LLD
// pins for the fix.
//
// Both tests will FAIL today because the conditional guards leave a
// spoofed AgentType in place. They will PASS once the GREEN agent
// removes the `if f.AgentType == ""` guards.

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// AC 13 (parseSnapshot path): a snapshot containing a Finding whose
// payload `agent_type` field is "spoof" must be overwritten to the
// dispatcher-supplied agentType ("owasp") in the persisted Finding.
func TestParseSnapshot_OverwritesSpoofedAgentType_AC13(t *testing.T) {
	snapshot := json.RawMessage(`{
		"findings": [
			{
				"title": "spoofed finding",
				"severity": "high",
				"file_path": "/x.py",
				"agent_type": "spoof"
			}
		],
		"score": 50
	}`)

	var findings []model.Finding
	scores := map[string]int{}

	// Proxy dispatched this to "owasp" — that identity MUST win.
	parseSnapshot(snapshot, "audit-1", "owasp", &findings, scores)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AgentType != "owasp" {
		t.Errorf("AC 13 violation: payload contained agent_type=spoof but proxy dispatched as owasp; got persisted AgentType = %q, want %q (unconditional overwrite required)",
			findings[0].AgentType, "owasp")
	}
}

// AC 13 (extractDeltaFindings path): a JSON-patch `add` op carrying
// `agent_type=spoof` must likewise be overwritten by the dispatcher's
// agentType. Same invariant, second code path.
func TestExtractDeltaFindings_OverwritesSpoofedAgentType_AC13(t *testing.T) {
	delta := json.RawMessage(`[
		{
			"op": "add",
			"path": "/findings/-",
			"value": {
				"title": "spoofed via delta",
				"severity": "high",
				"file_path": "/y.py",
				"agent_type": "spoof"
			}
		}
	]`)

	var findings []model.Finding

	extractDeltaFindings(delta, "audit-2", "owasp", &findings)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AgentType != "owasp" {
		t.Errorf("AC 13 violation: delta payload contained agent_type=spoof but proxy dispatched as owasp; got persisted AgentType = %q, want %q (unconditional overwrite required)",
			findings[0].AgentType, "owasp")
	}
}

// Defensive sub-case: an empty payload `agent_type` must STILL be
// filled in with the dispatcher's value. (This already works today;
// the test guards against a careless GREEN-phase fix that just
// inverted the condition.)
func TestParseSnapshot_EmptyAgentTypeStillFilled(t *testing.T) {
	snapshot := json.RawMessage(`{
		"findings": [{"title": "no agent_type", "severity": "low", "file_path": "/z.py"}],
		"score": 0
	}`)
	var findings []model.Finding
	scores := map[string]int{}

	parseSnapshot(snapshot, "audit-3", "cwe", &findings, scores)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AgentType != "cwe" {
		t.Errorf("empty payload agent_type must be filled by dispatcher: got %q, want cwe", findings[0].AgentType)
	}
}

// Defensive sub-case for the delta path: same invariant.
func TestExtractDeltaFindings_EmptyAgentTypeStillFilled(t *testing.T) {
	delta := json.RawMessage(`[
		{"op": "add", "path": "/findings/-", "value": {"title": "no agent_type", "severity": "low", "file_path": "/w.py"}}
	]`)
	var findings []model.Finding

	extractDeltaFindings(delta, "audit-4", "cwe", &findings)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AgentType != "cwe" {
		t.Errorf("empty payload agent_type must be filled by dispatcher: got %q, want cwe", findings[0].AgentType)
	}
}
