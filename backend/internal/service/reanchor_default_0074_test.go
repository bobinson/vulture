package service

// Feature 0074 P5, owner decision O6: VULTURE_LLM_QUOTE_REANCHOR defaults to
// ON, and Go must read it exactly as the Python agents do.
//
// The agent (shared.env.env_flag) moves a re-anchored row when the switch is
// unset, and treats true/1/yes/on and false/0/no/off case-insensitively, with
// an unset or unrecognised value taking the default. If the lineage pass keeps
// its own reader (unset = off, only the literal "true" arms it), the agent
// moves the finding while the lineage row refuses the matching window move,
// so the two halves of one evidence check disagree about where it sits.
// These tests pin the lineage pass to the agent's reading.
//
// Supersedes the unset case of TestReanchorDoesNotMoveTheLineUnlessArmed
// (lineage_scan_pass_test.go), which pins the pre-O6 default and must be
// re-signed together with this change.

import (
	"os"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const reanchorEnv = "VULTURE_LLM_QUOTE_REANCHOR"

// reanchoredWindowMoves runs one reanchored lineage check and reports whether
// the pass moved the row's window to the verified line.
func reanchoredWindowMoves(t *testing.T) bool {
	t.Helper()
	h := newPassHarness(t, []model.FindingLineage{llmRow("l-1", "fp-1")})
	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		LineageChecks: []model.LineageCheck{
			{LineageID: "l-1", Outcome: model.LineageOutcomeReanchored, LineStart: 42, LineEnd: 42},
		},
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	ev := h.evidence["l-1"]
	return ev.UpdateWindow && ev.LineStart == 42
}

// unsetEnv removes name for the rest of the test and restores it afterwards.
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "") // registers the restore
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}
}

// O6: with the switch unset the lineage pass moves the window, as the agent does.
func TestReanchorDefaultIsOnWhenUnset_0074(t *testing.T) {
	unsetEnv(t, reanchorEnv)
	if !reanchoredWindowMoves(t) {
		t.Fatal("O6: VULTURE_LLM_QUOTE_REANCHOR unset must arm the window move (Go default must equal the agent's)")
	}
}

// O6: Go reads every value as the agent does —
//   - blank or unrecognised values take the default (ON), never a hidden off;
//   - the agent's whole falsey token set disables the move (the rollback);
//   - the agent's truthy token set arms it (not only "true").
var reanchorTokenCases = []struct {
	value    string
	wantMove bool
}{
	{"", true}, {"  ", true}, {"maybe", true},
	{"false", false}, {"0", false}, {"no", false}, {"off", false}, {"FALSE", false}, {" Off ", false},
	{"true", true}, {"1", true}, {"yes", true}, {"on", true}, {"TRUE", true}, {" On ", true},
}

func TestReanchorTokensReadAsTheAgentDoes_0074(t *testing.T) {
	for _, c := range reanchorTokenCases {
		t.Run("value="+c.value, func(t *testing.T) {
			t.Setenv(reanchorEnv, c.value)
			if got := reanchoredWindowMoves(t); got != c.wantMove {
				t.Fatalf("VULTURE_LLM_QUOTE_REANCHOR=%q: window moved=%v, want %v, as in the agent (blank/unrecognised take the ON default)",
					c.value, got, c.wantMove)
			}
		})
	}
}

// C16: the lineage gate is the agent's conjunction, so VULTURE_LLM_QUOTE_VERIFY
// below enforce disarms the window move even with QUOTE_REANCHOR on — the O6
// rollback reaches the backend through either switch.
var reanchorVerifyCases = []struct {
	verify, reanchor string
	wantMove         bool
}{
	{"observe", "", false}, {"observe", "true", false}, {"OBSERVE", "", false},
	{"off", "true", false}, {"false", "", false},
	{"enforce", "false", false}, {"enforce", "", true}, {"", "", true},
	{"enforced", "", true}, // unrecognised: the enforce default, plus a warning
}

func TestReanchorGateHonoursQuoteVerify_0074(t *testing.T) {
	for _, c := range reanchorVerifyCases {
		t.Run("verify="+c.verify+"/reanchor="+c.reanchor, func(t *testing.T) {
			t.Setenv("VULTURE_LLM_QUOTE_VERIFY", c.verify)
			t.Setenv(reanchorEnv, c.reanchor)
			if got := reanchoredWindowMoves(t); got != c.wantMove {
				t.Fatalf("VERIFY=%q REANCHOR=%q: window moved=%v, want %v (agent: mode==enforce AND reanchor)",
					c.verify, c.reanchor, got, c.wantMove)
			}
		})
	}
}
