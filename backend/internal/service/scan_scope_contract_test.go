package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §6.5 — the Go half of the cross-language SCOPE pin.
//
// WHY A SHARED FIXTURE AND NOT A GO-LOCAL ONE. `pruned_dirs` is written by the
// Python walker and consumed only here, and both failure directions are
// silent (see the `_doc` block in the contract file). A Go test that invents
// its own prefixes proves that this predicate is self-consistent, which was
// never in doubt; it cannot see the walker start reporting a bare `.vscode`
// again, and that single change would make every autorun lineage row
// permanently uncloseable while every test in both suites stayed green.
//
// So this reads the SAME file the Python suite asserts its walker against:
//
//	agents/shared/tests/contract/0091_scan_scope.json
//	agents/shared/tests/contract/test_0091_scan_scope.py
//
// and derives its expectations from the `scanned` list rather than from a
// second hand-written list: a file the walker READ must be in scope, and a
// file it skipped must not be. That coupling is the contract; the explicit
// `out_of_scope` entries are the extra paths that carry no finding of their
// own but must still be excluded.

type scopeContract struct {
	Cases []scopeContractCase `json:"cases"`
}

type scopeContractCase struct {
	Name string `json:"name"`
	// No scan_editor_config field: VULTURE_SCAN_EDITOR_CONFIG was retired with
	// the 0091 flag clean-up, the autorun allowlist is unconditional, and this
	// side never read the value anyway.
	Scanned            []string `json:"scanned"`
	PrunedDirs         []string `json:"pruned_dirs"`
	ExplicitOutOfScope []string `json:"out_of_scope"`
}

// scopeContractPath resolves the shared contract from this package's
// directory. A hard failure, never a skip: a pin that quietly stops running is
// worse than no pin, because the report still says green.
func scopeContractPath(t *testing.T) string {
	t.Helper()
	// backend/internal/service -> backend/internal -> backend -> repo root
	p := filepath.Join("..", "..", "..",
		"agents", "shared", "tests", "contract", "0091_scan_scope.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("shared 0091 scope contract not found at %s: %v\n"+
			"This file is the cross-language pin between the Python walker's pruned_dirs "+
			"and this package's scanScope; if it moved, update BOTH suites that read it.", p, err)
	}
	return p
}

func loadScopeContract(t *testing.T) scopeContract {
	t.Helper()
	raw, err := os.ReadFile(scopeContractPath(t))
	if err != nil {
		t.Fatalf("read scope contract: %v", err)
	}
	var c scopeContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse scope contract: %v", err)
	}
	if len(c.Cases) == 0 {
		t.Fatal("the scope contract declares no cases; the pin would assert nothing")
	}
	return c
}

// TestScanScopeAgreesWithTheWalkersPrunedDirs feeds the real recorded
// `pruned_dirs` into the real scanScope and checks both directions.
func TestScanScopeAgreesWithTheWalkersPrunedDirs(t *testing.T) {
	for _, tc := range loadScopeContract(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			// A root scan: the agent walked the target root itself, so there is
			// no offset and the row paths are already root-relative. That is
			// the configuration D2 changed and the one the contract describes.
			scope := newScanScope(&model.ScanResult{
				ResultSchema: model.ScanResultSchemaEvidence,
				PrunedDirs:   tc.PrunedDirs,
			}, TargetIdentity{})
			if scope == nil {
				t.Fatal("a result declaring the evidence schema must produce a known scope")
			}

			// Direction one: everything the walker READ is in scope. This is
			// the half that keeps a scanned autorun file closeable.
			for _, rel := range tc.Scanned {
				if reason := scope.exclusion(rel); reason != "" {
					t.Errorf("the walker SCANNED %q, but scope excludes it (%s).\n"+
						"pruned_dirs was %v. A lineage row there would be recorded out_of_scope on "+
						"every scan, and because the scope check returns before the tier rules it "+
						"could never close — a repaired finding would stay open forever.",
						rel, reason, tc.PrunedDirs)
				}
			}

			// Direction two: everything it skipped is out of scope. This is the
			// half that stops a scan from closing a finding it never looked at.
			for _, rel := range tc.ExplicitOutOfScope {
				if scope.contains(rel) {
					t.Errorf("the walker did NOT read %q, but scope admits it.\n"+
						"pruned_dirs was %v. The deterministic tier closes on absence, so this row "+
						"would be marked fixed while its code was never read.",
						rel, tc.PrunedDirs)
				}
				if containsString(tc.Scanned, rel) {
					t.Errorf("the contract lists %q as both scanned and out_of_scope; one of the "+
						"two lists is stale", rel)
				}
			}
		})
	}
}
