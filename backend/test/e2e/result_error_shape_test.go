//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// A result's `error` member is read for its text, but its SHAPE is the agent's
// business: an object, a number or a bool must cost nothing else in the
// result. In particular it must never cost the feature-0091 scope keys — a
// scan that says it enumerated a partial set (`scan_truncated`) closes
// nothing, and losing that key turns the truncated scan into a clean one that
// closes every deterministic row it did not reach.
func TestResultErrorOfAnyShapeKeepsTheScanScope(t *testing.T) {
	truncated := `{"findings":[],"summary":"cwe","score":100,"result_schema":2,` +
		`"scan_truncated":true,"pruned_dirs":[],"error":{"code":"enumeration_capped"}}`
	cwe := newScriptedAgent(t, mappingCWEResult, truncated)
	h := newLabelsHarness(t, map[string]*scriptedAgent{"cwe": cwe})

	h.run(t, []string{"cwe"}, nil)
	rows := h.waitLineage(t, "scan 1's cwe row", func(r []labelledLineageRow) bool {
		return len(rowsOfAgent(r, "cwe")) == 1
	})
	row := rowsOfAgent(rows, "cwe")[0]

	second := h.run(t, []string{"cwe"}, nil)
	want := "out_of_scope@" + second.ID
	deadline := time.Now().Add(10 * time.Second)
	status, events := lineageDetail(t, h.addr, row.ID)
	for ; !containsEvent(events, want) && status == "open" && time.Now().Before(deadline); status, events = lineageDetail(t, h.addr, row.ID) {
		time.Sleep(50 * time.Millisecond)
	}
	if status != "open" {
		t.Fatalf("a truncated scan whose `error` is an object closed deterministic row %s: status %q, events %v",
			row.ID, status, events)
	}
	if !containsEvent(events, want) {
		t.Fatalf("the truncated scan must record %s on row %s (its scope survived the parse), events %v", want, row.ID, events)
	}
}

func containsEvent(events []string, want string) bool {
	for _, e := range events {
		if strings.EqualFold(e, want) {
			return true
		}
	}
	return false
}
