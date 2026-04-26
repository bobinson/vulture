package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var oracleCmd string
var oracleArgs []string

func init() {
	if bin := os.Getenv("PIPELINE_ORACLE"); bin != "" {
		oracleCmd = bin
		return
	}
	oracleCmd = "java"
	oracleArgs = []string{"-jar", "../oracle/build/libs/pipeline-oracle.jar"}
}

func runOracle(t *testing.T, args ...string) []byte {
	t.Helper()
	full := append(oracleArgs, args...)
	out, err := exec.Command(oracleCmd, full...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("oracle failed: %v\nstderr: %s", err, ee.Stderr)
		}
		t.Fatalf("oracle failed: %v", err)
	}
	return out
}

type AdvanceInput struct {
	Status string   `json:"status"`
	Stages []string `json:"stages"`
	Index  int      `json:"index"`
}

type AdvanceResult struct {
	Status string `json:"status"`
	Index  int    `json:"index"`
}

func oracleAdvance(t *testing.T, input AdvanceInput, outcome string) AdvanceResult {
	t.Helper()
	j, _ := json.Marshal(input)
	out := runOracle(t, "advance", string(j), outcome)
	var r AdvanceResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("parse advance: %v (raw: %s)", err, out)
	}
	return r
}

type ExpandInput struct {
	Stages    []string `json:"stages"`
	HasSource bool     `json:"has_source"`
}

type ExpandResult struct {
	Stages []string `json:"stages"`
}

func oracleExpand(t *testing.T, input ExpandInput) ExpandResult {
	t.Helper()
	j, _ := json.Marshal(input)
	out := runOracle(t, "expand", string(j))
	var r ExpandResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("parse expand: %v (raw: %s)", err, out)
	}
	return r
}

var validStatuses = map[string]bool{
	"pending": true, "scan_running": true, "discover_running": true,
	"prove_running": true, "completed": true, "failed": true,
}

var stageOrder = map[string]int{"scan": 0, "discover": 1, "prove": 2}

// Exhaustive advance: 6 statuses x 2 outcomes x 4 indices = 48 tests
func TestAdvance_Exhaustive(t *testing.T) {
	statuses := []string{"pending", "scan_running", "discover_running", "prove_running", "completed", "failed"}
	outcomes := []string{"completed", "failed"}
	stages := []string{"scan", "discover", "prove"}

	for _, status := range statuses {
		for _, outcome := range outcomes {
			for idx := 0; idx <= 3; idx++ {
				t.Run(fmt.Sprintf("s=%s/o=%s/i=%d", status, outcome, idx), func(t *testing.T) {
					input := AdvanceInput{Status: status, Stages: stages, Index: idx}
					r := oracleAdvance(t, input, outcome)

					if !validStatuses[r.Status] {
						t.Errorf("invalid status: %q", r.Status)
					}
					// Terminal states absorbing
					if status == "completed" || status == "failed" || status == "pending" {
						if r.Status != status {
							t.Errorf("terminal %q changed to %q", status, r.Status)
						}
					}
					// Failure always reaches failed
					if outcome == "failed" && status != "completed" && status != "failed" && status != "pending" {
						if r.Status != "failed" {
							t.Errorf("failure outcome → %q, expected failed", r.Status)
						}
					}
					// Index never decreases
					if r.Index < idx {
						t.Errorf("index decreased: %d → %d", idx, r.Index)
					}
					// Index increments by at most 1
					if r.Index > idx+1 {
						t.Errorf("index jumped: %d → %d", idx, r.Index)
					}
				})
			}
		}
	}
}

// Exhaustive expand: 8 subsets x 2 source flags = 16 tests
func TestExpand_Exhaustive(t *testing.T) {
	subsets := [][]string{
		{}, {"scan"}, {"discover"}, {"prove"},
		{"scan", "discover"}, {"scan", "prove"}, {"discover", "prove"},
		{"scan", "discover", "prove"},
	}
	for _, stages := range subsets {
		for _, src := range []bool{true, false} {
			t.Run(fmt.Sprintf("s=%v/src=%v", stages, src), func(t *testing.T) {
				r := oracleExpand(t, ExpandInput{Stages: stages, HasSource: src})
				// No duplicates
				seen := map[string]bool{}
				for _, s := range r.Stages {
					if seen[s] {
						t.Errorf("duplicate: %s", s)
					}
					seen[s] = true
				}
				// Canonical order
				for i := 1; i < len(r.Stages); i++ {
					if stageOrder[r.Stages[i]] <= stageOrder[r.Stages[i-1]] {
						t.Errorf("not in order: %v", r.Stages)
					}
				}
				// All requested present
				for _, req := range stages {
					if !seen[req] {
						t.Errorf("%q missing from %v", req, r.Stages)
					}
				}
				// Empty in → empty out
				if len(stages) == 0 && len(r.Stages) != 0 {
					t.Errorf("empty in → %v", r.Stages)
				}
			})
		}
	}
}

// Cross-check with Isabelle lemmas
func TestExpand_KnownResults(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		src  bool
		want string
	}{
		{"prove+src", []string{"prove"}, true, "scan,discover,prove"},
		{"prove-src", []string{"prove"}, false, "scan,discover,prove"},
		{"disc+src", []string{"discover"}, true, "scan,discover"},
		{"disc-src", []string{"discover"}, false, "discover"},
		{"scan+src", []string{"scan"}, true, "scan"},
		{"scan-src", []string{"scan"}, false, "scan"},
		{"empty", []string{}, true, ""},
		{"all", []string{"scan", "discover", "prove"}, true, "scan,discover,prove"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := oracleExpand(t, ExpandInput{Stages: tc.in, HasSource: tc.src})
			got := strings.Join(r.Stages, ",")
			if got != tc.want {
				t.Errorf("got [%s], want [%s]", got, tc.want)
			}
		})
	}
}

// Three-stage lifecycle
func TestAdvance_Lifecycle(t *testing.T) {
	stages := []string{"scan", "discover", "prove"}

	r1 := oracleAdvance(t, AdvanceInput{Status: "scan_running", Stages: stages, Index: 0}, "completed")
	if r1.Status != "discover_running" || r1.Index != 1 {
		t.Fatalf("after scan: %s/%d", r1.Status, r1.Index)
	}

	r2 := oracleAdvance(t, AdvanceInput{Status: r1.Status, Stages: stages, Index: r1.Index}, "completed")
	if r2.Status != "prove_running" || r2.Index != 2 {
		t.Fatalf("after discover: %s/%d", r2.Status, r2.Index)
	}

	r3 := oracleAdvance(t, AdvanceInput{Status: r2.Status, Stages: stages, Index: r2.Index}, "completed")
	if r3.Status != "completed" {
		t.Fatalf("after prove: %s", r3.Status)
	}
}
