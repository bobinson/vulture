package service

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0102 D24 — unit tests for the per-file AST lineage guard
// (lineage_scan_pass_ast_guard.go). The business contract lives in
// backend/test/e2e/lineage_ast_guard_0102_test.go; these pin the pure
// decision and the edges E2E cannot reach cheaply.

const guardRoot = "/home/dev/proj"

func guardScope() *scanScope { return &scanScope{root: guardRoot} }

// placedGuard pairs a guard with the scope the pass places rows by.
type placedGuard struct {
	g     *astGuard
	scope *scanScope
}

// guardOn builds the guard as closeForAgent does; the error only feeds a log.
func guardOn(raw json.RawMessage, scope *scanScope) placedGuard {
	g, _ := newASTGuard(raw, scope)
	return placedGuard{g: g, scope: scope}
}

// readableGuard is guardOn for a coverage that must decode cleanly.
func readableGuard(t *testing.T, raw json.RawMessage, scope *scanScope) placedGuard {
	t.Helper()
	g, err := newASTGuard(raw, scope)
	if err != nil {
		t.Fatalf("a readable ast_coverage must not report an error, got %v", err)
	}
	return placedGuard{g: g, scope: scope}
}

// holds places row as apply does (scope.locate) and asks the guard whether
// the pass must hold it `unconfirmed` instead of closing it.
func (pg placedGuard) holds(row *model.FindingLineage) bool {
	rel, _ := pg.scope.locate(row.FilePath)
	return pg.g.holdReason(row, rel) != ""
}

func guardRow(category, filePath string) *model.FindingLineage {
	return &model.FindingLineage{
		ID: "row-" + category, Fingerprint: "fp-" + category, AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen,
		Provenance:    "skill",
		Category:      category,
		FilePath:      filePath,
	}
}

// coverage renders a well-formed ast_coverage with the given keys.
func coverage(t *testing.T, breaker bool, keys ...string) json.RawMessage {
	t.Helper()
	if keys == nil {
		keys = []string{}
	}
	raw, err := json.Marshal(map[string]any{
		"files": map[string]any{
			"parsed":                   10,
			"fallback":                 map[string]int{"parse_error": len(keys)},
			"fallback_paths":           keys,
			"fallback_paths_truncated": false,
			"fallback_keys":            keys,
			"breaker_tripped":          breaker,
		},
		"workers": map[string]any{"count": 1, "breaker_tripped": breaker},
	})
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	return raw
}

var astOwned = []string{"CWE-22", "CWE-918", "CWE-78"}

// probeOwned asks g about a row in EVERY AST-owned category on every path: the
// contract never distinguishes CWE-22, CWE-918 and CWE-78.
func probeOwned(t *testing.T, g placedGuard, paths []string, want bool) {
	t.Helper()
	for _, cat := range astOwned {
		for _, p := range paths {
			if got := g.holds(guardRow(cat, p)); got != want {
				t.Errorf("holds(%s on %q) = %v, want %v", cat, p, got, want)
			}
		}
	}
}

func TestASTGuardAbsentCoverageIsNoGuard(t *testing.T) {
	for name, raw := range map[string]json.RawMessage{"nil": nil, "empty": {}} {
		if g, err := newASTGuard(raw, guardScope()); g != nil || err != nil {
			t.Fatalf("%s: an ABSENT ast_coverage (older agent, or no AST layer) must yield no guard, got %+v, %v", name, g, err)
		}
	}
}

func TestASTGuardNilGuardHoldsNothing(t *testing.T) {
	if (placedGuard{scope: guardScope()}).holds(guardRow("CWE-22", "src/a.js")) {
		t.Fatal("a nil guard must hold nothing — the pass calls it unconditionally")
	}
}

// TestASTGuardHolds is the per-row decision for an AST-owned category. Each
// case name states the rule it pins.
func TestASTGuardHolds(t *testing.T) {
	nonASCII := "src/données/ルート_файл.js"
	long := "src/" + strings.Repeat("deeply_nested_module_directory/", 8) + "handler.ts"
	if len(long) <= 200 {
		t.Fatalf("precondition: long path must exceed 200 chars, got %d", len(long))
	}
	// Thousands of parse_error fallbacks in a 50k-file repo are handled per
	// file, not by freezing every owned row.
	many := make([]string, 20000)
	for i := range many {
		many[i] = "gen/f" + strings.Repeat("x", i%7) + "_" + strconv.Itoa(i) + ".js"
	}
	onA, manyCov := coverage(t, false, "src/a.js"), coverage(t, false, many...)
	sub, onHandler := &scanScope{root: guardRoot, offset: "svc"}, coverage(t, false, "handler.js")
	// fallback_paths is safe_path-rendered and 200-capped for humans.
	displayOnly := json.RawMessage(`{"files":{
		"fallback_paths":["src/a.js"],"fallback_paths_truncated":true,
		"fallback_keys":[],"breaker_tripped":false}}`)

	cases := []struct {
		name  string
		cov   json.RawMessage
		scope *scanScope
		paths []string
		want  bool
	}{
		{"a fallback file is held", onA, guardScope(), []string{"src/a.js"}, true},
		{"a file NOT in fallback_keys was re-read by the AST tier and closes as today",
			onA, guardScope(), []string{"src/b.js"}, false},
		{"breaker_tripped holds even a file absent from fallback_keys",
			coverage(t, true), guardScope(), []string{"src/never_listed.js"}, true},
		{"membership is fallback_keys alone: fallback_paths and a truncated display list are display-only",
			displayOnly, guardScope(), []string{"src/a.js"}, false},
		{"an ABSOLUTE row under the root is placed root-relative before the membership test",
			onA, guardScope(), []string{guardRoot + "/src/a.js"}, true},
		{"an absolute row on a parsed file is not held", onA, guardScope(), []string{guardRoot + "/src/b.js"}, false},
		{"a row that cannot be placed in target coordinates cannot be proven re-read, so it is held",
			coverage(t, false), guardScope(),
			[]string{"/mnt/source/proj/src/a.js", guardRoot + "-backup/src/a.js", "", "   "}, true},
		{"with no scope no key can be placed by the scan offset, so every owned row is held",
			onA, nil, []string{guardRoot + "/src/b.js", "src/a.js", "src/b.js"}, true},
		{"a sub-path scan's key is placed under the scan offset, meeting relative and absolute rows",
			onHandler, sub, []string{"svc/handler.js", guardRoot + "/svc/handler.js"}, true},
		{"a sibling file the sub-path scan parsed is not held", onHandler, sub, []string{"svc/other.js"}, false},
		{"both sides normalise to one form: no ./, no leading or trailing /, trimmed",
			coverage(t, false, "./src/a.js", "lib/b.py"), guardScope(),
			[]string{"src/a.js", "./src/a.js", "lib/b.py", " lib/b.py "}, true},
		{"the display list's hard cases (non-ASCII, over 200 chars) match their lossless key byte-exact",
			coverage(t, false, nonASCII, long), guardScope(), []string{nonASCII, long, guardRoot + "/" + nonASCII}, true},
		{"the last of 20000 fallback keys is held", manyCov, guardScope(), []string{many[len(many)-1]}, true},
		{"a large key set is still per-file membership, never hold-all",
			manyCov, guardScope(), []string{"gen/not_listed.js"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { probeOwned(t, readableGuard(t, tc.cov, tc.scope), tc.paths, tc.want) })
	}
}

// TestASTGuardMalformedPresentCoverageHolds: a PRESENT ast_coverage the
// backend cannot read must hold every owned row (fail safe) — present-but-
// unreadable is never read as absent. Each payload names no usable file, so
// only hold-all can hold. Each must also report why, for the pass's log line.
func TestASTGuardMalformedPresentCoverageHolds(t *testing.T) {
	cases := map[string]string{
		"fallback_keys not a list":   `{"files":{"fallback_keys":"src/a.js","breaker_tripped":false}}`,
		"fallback_keys bad element":  `{"files":{"fallback_keys":[1],"breaker_tripped":false}}`,
		"fallback_keys missing":      `{"files":{"breaker_tripped":false}}`,
		"fallback_keys null":         `{"files":{"fallback_keys":null,"breaker_tripped":false}}`,
		"breaker_tripped not a bool": `{"files":{"fallback_keys":[],"breaker_tripped":"no"}}`,
		"breaker_tripped missing":    `{"files":{"fallback_keys":[]}}`,
		"files missing":              `{"grammars":{}}`,
		"files not an object":        `{"files":["src/a.js"]}`,
		"coverage an array":          `[]`,
		"coverage a string":          `"degraded"`,
		"coverage null":              `null`,
		"coverage not json":          `{"files":`,
		"fallback key absolute":      `{"files":{"fallback_keys":["/src/a.js"],"breaker_tripped":false}}`,
		"fallback key escapes root":  `{"files":{"fallback_keys":["../a.js"],"breaker_tripped":false}}`,
		"fallback key the root":      `{"files":{"fallback_keys":["."],"breaker_tripped":false}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			g, err := newASTGuard(json.RawMessage(raw), guardScope())
			if err == nil {
				t.Fatal("a present, unreadable ast_coverage must report why it holds every owned row")
			}
			probeOwned(t, placedGuard{g: g, scope: guardScope()}, []string{"src/b.js"}, true)
		})
	}
}

// TestASTGuardNeverHoldsWhatTheASTDoesNotOwn: whatever the coverage says —
// fallback, breaker, unreadable — the guard never holds a category the AST
// tier does not own, nor an LLM-tier row: that tier closes only on `gone`
// evidence (0091), never on absence, so the guard has nothing to protect.
func TestASTGuardNeverHoldsWhatTheASTDoesNotOwn(t *testing.T) {
	llm := guardRow("CWE-22", "src/a.js")
	llm.Provenance = "llm_l5_verified"
	rows := []*model.FindingLineage{llm}
	for _, cat := range []string{"CWE-79", "CWE-220", "CWE-2", "CWE-7", "CWE-918x", "", "injection"} {
		rows = append(rows, guardRow(cat, "src/a.js"))
	}
	for _, raw := range []json.RawMessage{
		coverage(t, false, "src/a.js"), coverage(t, true, "src/a.js"), json.RawMessage(`"malformed"`),
	} {
		requireNotHeld(t, guardOn(raw, guardScope()), rows)
	}
}

func requireNotHeld(t *testing.T, g placedGuard, rows []*model.FindingLineage) {
	t.Helper()
	for _, row := range rows {
		if g.holds(row) {
			t.Fatalf("category %q (provenance %q) is not AST-owned; the guard must never hold it",
				row.Category, row.Provenance)
		}
	}
}

// TestASTGuardOwnsZeroPaddedCWE: "CWE-022" IS CWE-22 (0096 M12), so a padded
// id on a fallback file is held exactly like the canonical one.
func TestASTGuardOwnsZeroPaddedCWE(t *testing.T) {
	g := readableGuard(t, coverage(t, false, "src/a.js"), guardScope())
	for _, cat := range []string{"CWE-022", "CWE-0918", "CWE-078"} {
		if !g.holds(guardRow(cat, "src/a.js")) {
			t.Errorf("holds(%s on a fallback file) = false, want true", cat)
		}
	}
}

// TestASTGuardDoesNotMutateTheRow: holds is a pure read.
func TestASTGuardDoesNotMutateTheRow(t *testing.T) {
	g := readableGuard(t, coverage(t, false, "src/a.js"), guardScope())
	row := guardRow("CWE-22", guardRoot+"/src/a.js")
	before := *row
	_ = g.holds(row)
	if !reflect.DeepEqual(*row, before) {
		t.Fatalf("holds must not mutate the row: before %+v, after %+v", before, *row)
	}
}

// astPass threads cov through the real pass — ScanResult.ASTCoverage ->
// closeForAgent -> apply — over a CWE-22 row "d-22" and a CWE-79 control
// "d-79", both on detRow's file src/config.py.
func astPass(t *testing.T, cov json.RawMessage) *passHarness {
	t.Helper()
	held := detRow("d-22", "fp-22")
	held.Category = "CWE-22"
	control := detRow("d-79", "fp-79")
	control.Category = "CWE-79"
	h := newPassHarness(t, []model.FindingLineage{held, control})
	if err := h.svc.RecordScanOutcome(passAudit(), passSource(), "cwe", &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		ASTCoverage:  cov,
	}); err != nil {
		t.Fatalf("record scan outcome: %v", err)
	}
	return h
}

// requireIDs fails unless got holds exactly want (sorted), in any order.
func requireIDs(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(slices.Sorted(slices.Values(got)), want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// reasonedHold matches the `unconfirmable` event that records why row id was
// held, with a non-blank reason.
func reasonedHold(id string) func(*model.LineageEvent) bool {
	return func(e *model.LineageEvent) bool {
		return e.LineageID == id && e.EventType == model.LineageEventUnconfirmable && strings.TrimSpace(e.Notes) != ""
	}
}

// TestPassHoldsASTRowOnFallbackFile: the held row goes through markUnconfirmed
// (memory synced "open", never "resolved"); the CWE-79 control on the same
// file closes as today.
func TestPassHoldsASTRowOnFallbackFile(t *testing.T) {
	h := astPass(t, coverage(t, false, "src/config.py"))

	requireIDs(t, "fixed (only the CWE-79 control may close)", h.fixed, "d-79")
	requireIDs(t, "unconfirmed (the CWE-22 row on a fallback file must be held)", h.unconfirmed, "d-22")
	if got := h.memory["fp-22"]; got != "open" {
		t.Fatalf("a held row syncs memory to %q, got %q", "open", got)
	}
	if !slices.ContainsFunc(h.events, reasonedHold("d-22")) {
		t.Fatalf("expected an unconfirmable event with a reason recording why d-22 was held, got %+v", h.events)
	}
}

// TestPassAbsentASTCoverageClosesAsToday is the control for the threading: no
// ast_coverage, no guard.
func TestPassAbsentASTCoverageClosesAsToday(t *testing.T) {
	h := astPass(t, nil)

	requireIDs(t, "fixed (absent ast_coverage keeps today's closure)", h.fixed, "d-22", "d-79")
	requireIDs(t, "unconfirmed (absent ast_coverage holds nothing)", h.unconfirmed)
}
