package model

// Feature 0074 P4 (plan §5.5 item 3, AC19, AC31, version-skew rule).
//
// The agent publishes two run-level counters on its result — llm_emitted
// (LLM rows before the agent's own dedup) and llm_collapsed_agent (LLM rows
// that dedup dropped) — as new omitempty fields of ScanResult. Go needs both
// to derive llm_lost, and it must be able to tell an OLDER agent (counters
// absent → buckets "unavailable") from a new agent that genuinely emitted
// zero (counters present and 0). So an explicit 0 must survive decoding.
//
// Tested through the wire (decode, then re-encode) rather than by field name,
// so the contract is the JSON the agent sends, not a Go identifier.

import (
	"encoding/json"
	"strings"
	"testing"
)

// roundTripScanResult decodes an agent payload into ScanResult and encodes it
// again: whatever ScanResult keeps is what the backend can act on.
func roundTripScanResult(t *testing.T, payload string) string {
	t.Helper()
	var r ScanResult
	if err := json.Unmarshal([]byte(payload), &r); err != nil {
		t.Fatalf("decode %s: %v", payload, err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(b)
}

func assertWireHas(t *testing.T, wire string, frags ...string) {
	t.Helper()
	for _, f := range frags {
		if !strings.Contains(wire, f) {
			t.Errorf("ScanResult dropped %s; re-encoded as %s", f, wire)
		}
	}
}

// AC19/AC31: both counters decode and are kept.
func TestScanResultDecodesLLMDedupCounters_0074(t *testing.T) {
	wire := roundTripScanResult(t, `{"findings":[],"result_schema":2,"llm_emitted":7,"llm_collapsed_agent":2}`)
	assertWireHas(t, wire, `"llm_emitted":7`, `"llm_collapsed_agent":2`)
}

// Version skew: a counter of ZERO is a fact and must survive (an omitempty
// plain int would erase it and make a new agent look like an old one).
func TestScanResultKeepsAnExplicitZeroCounter_0074(t *testing.T) {
	wire := roundTripScanResult(t, `{"findings":[],"llm_emitted":0,"llm_collapsed_agent":0}`)
	assertWireHas(t, wire, `"llm_emitted":0`, `"llm_collapsed_agent":0`)
}

// Version skew: an older agent's payload carries no counters, and none are
// invented (omitempty) — absence is what marks the buckets unavailable.
func TestScanResultOlderAgentHasNoCounters_0074(t *testing.T) {
	wire := roundTripScanResult(t, `{"findings":[],"score":70}`)
	if strings.Contains(wire, "llm_emitted") || strings.Contains(wire, "llm_collapsed_agent") {
		t.Errorf("counters invented for an older agent: %s", wire)
	}
}
