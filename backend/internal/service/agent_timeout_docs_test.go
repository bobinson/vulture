package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Feature 0078 §14.2 / §14.5. `timeoutMarginWarning` is the runtime half of this
// invariant; the docs are the other half, and they are the ONLY half an operator
// reads before starting anything. §14.5 names "the docs stated the insufficient
// rule" as the failure mode that let the 7500/7200/600 misconfiguration through
// review, so a surviving restatement of `PROXY >= MAX_AUDIT` is a live defect and
// not a cosmetic one — the inverted form (`MAX_AUDIT >= PROXY`) implies
// `PROXY <= MAX_AUDIT`, i.e. it guarantees the failure §14.2 diagnoses.
//
// These tests are that control, made machine-checkable: no comment in
// `env.example` may state an ordering between the backend per-agent timeout and
// the agent whole-audit ceiling without also naming the one-LLM-call margin.
// A restatement of the superseded rule (`PROXY >= MAX_AUDIT`) is a regression
// even when the canonical MARGIN RULE block elsewhere in the file is correct,
// because an operator configures from the block next to the variable.

// Naming either side of the ordering.
var timeoutOrderingSubjects = []string{
	"per-agent timeout",
	"agent ceiling",
	"VULTURE_AGENT_PROXY_TIMEOUT_SEC",
}

// Asserting a relation between them.
var timeoutOrderingRelations = []string{
	">=",
	"<=",
	"at or below",
	"at least",
	"no lower than",
	"no higher than",
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func readRepoFileLines(t *testing.T, name string) []string {
	t.Helper()
	path := filepath.Join("..", "..", "..", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return strings.Split(string(data), "\n")
}

// statesTimeoutOrdering reports whether one comment line asserts a relation
// between the two timeouts.
func statesTimeoutOrdering(line string) bool {
	if !strings.HasPrefix(strings.TrimSpace(line), "#") {
		return false
	}
	return containsAny(line, timeoutOrderingSubjects) &&
		containsAny(line, timeoutOrderingRelations)
}

// Scoped to env.example: it is the only file this change owns. The same scan
// applies verbatim to CLAUDE.md and docker-compose.yml, which still restate the
// superseded rule — add them to a file list here in the change that corrects
// their prose, not before, or this guard ships red.
func TestEnvExampleTimeoutOrderingAlwaysStatesTheMargin(t *testing.T) {
	lines := readRepoFileLines(t, "env.example")
	for i, line := range lines {
		if !statesTimeoutOrdering(line) {
			continue
		}
		// The clause may wrap onto the next comment line.
		window := line
		if i+1 < len(lines) {
			window += " " + lines[i+1]
		}
		if !strings.Contains(window, "LLM_CALL") {
			t.Errorf("env.example:%d orders the backend per-agent timeout against the "+
				"agent whole-audit ceiling without the one-LLM-call margin "+
				"(feature 0078 §14.2 — PROXY >= MAX_AUDIT is the superseded, "+
				"insufficient rule): %q", i+1, strings.TrimSpace(line))
		}
	}
}

func TestEnvExampleStatesCorrectedInvariantBothWays(t *testing.T) {
	body := strings.Join(readRepoFileLines(t, "env.example"), "\n")
	// Stated from the backend's side (the canonical MARGIN RULE block) ...
	if !strings.Contains(body, "PROXY >= MAX_AUDIT + LLM_CALL") {
		t.Error("env.example no longer states the MARGIN RULE from the backend side " +
			"(PROXY >= MAX_AUDIT + LLM_CALL)")
	}
	// ... and from the agent's side, where the operator actually sets the
	// ceiling. Stating only one side is how the inverted restatement survived.
	if !strings.Contains(body,
		"VULTURE_AGENT_PROXY_TIMEOUT_SEC - VULTURE_LLM_CALL_TIMEOUT_SEC") {
		t.Error("the VULTURE_AGENT_MAX_AUDIT_SECONDS block must state the margin from " +
			"the agent side: MAX_AUDIT <= VULTURE_AGENT_PROXY_TIMEOUT_SEC - " +
			"VULTURE_LLM_CALL_TIMEOUT_SEC")
	}
}
