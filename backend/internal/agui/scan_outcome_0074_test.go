package agui

// Feature 0074 P4 (plan §5.5 item 3, AC19, version-skew rule): the agent's
// llm_emitted / llm_collapsed_agent counters must reach Go through the SAME
// parser that already carries the 0091 keys into DrainResult.ScanOutcomes,
// with an explicit zero distinguishable from absence (an older agent).
// Asserted through the wire form of the parsed ScanResult, not field names.

import (
	"encoding/json"
	"strings"
	"testing"
)

func parsedOutcomeWire(t *testing.T, snapshot string) string {
	t.Helper()
	b, err := json.Marshal(ParseScanOutcome(json.RawMessage(snapshot)))
	if err != nil {
		t.Fatalf("encode parsed outcome: %v", err)
	}
	return string(b)
}

// AC19: the counters ride the result snapshot into ScanOutcomes.
func TestParseScanOutcomeCarriesLLMDedupCounters_0074(t *testing.T) {
	wire := parsedOutcomeWire(t, `{"findings":[],"result_schema":2,"llm_emitted":5,"llm_collapsed_agent":1}`)
	for _, frag := range []string{`"llm_emitted":5`, `"llm_collapsed_agent":1`} {
		if !strings.Contains(wire, frag) {
			t.Errorf("ParseScanOutcome dropped %s: %s", frag, wire)
		}
	}
}

// Version skew: zero is kept, absence stays absent.
func TestParseScanOutcomeZeroVersusAbsent_0074(t *testing.T) {
	zero := parsedOutcomeWire(t, `{"findings":[],"llm_emitted":0,"llm_collapsed_agent":0}`)
	if !hasBothZeroCounters(zero) {
		t.Errorf("an explicit zero was erased (would read as an older agent): %s", zero)
	}
	absent := parsedOutcomeWire(t, `{"findings":[],"result_schema":2}`)
	if strings.Contains(absent, "llm_emitted") || strings.Contains(absent, "llm_collapsed_agent") {
		t.Errorf("counters invented for an agent that sent none: %s", absent)
	}
}

func hasBothZeroCounters(wire string) bool {
	return strings.Contains(wire, `"llm_emitted":0`) && strings.Contains(wire, `"llm_collapsed_agent":0`)
}
