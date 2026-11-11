package handler

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0104 A2 (OD-2; G19 (c)): the cwe agent reports a file's hint-only AST rows of one
// rule as ONE row whose validation.flow.sinks names every member's sink line, and refuses the
// group where another of its own rows stands at a member line and would be reconciled with it
// (R1, R2). No backend code changes for A2: these tests pin what the cross-agent merge does
// with what the agent now sends. The rows are the agent's own output (its validate stage, LLM
// off) for small probe files: paths moved under root0104, each code window cut to its cited
// line, and only keys the merge reads kept.

const root0104 = "/scan"

// group0104 is the agent's group row: CWE-22 at line 4 standing for the sinks at 4, 8, 12, 16.
var group0104 = []string{
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"description": "Potential path traversal: untrusted input reaches 4 sinks, the first at line 4",
		"file_path": "/scan/src/reader.js",
		"line_start": 4,
		"line_end": 4,
		"check_id": "cwe.input_validation.path_traversal",
		"code_snippet": "4:   fs.readFile(fileName, cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {
			"status": "suspicious",
			"confidence": 0.5,
			"checks": [
				{"id": "path", "result": "neutral", "weight": 0.0},
				{"id": "input_validation", "result": "no_identifiers", "weight": 0.0},
				{"id": "sanitizer", "result": "absent", "weight": 0.0},
				{"id": "obligation", "result": "discharged", "weight": 0.0},
				{"id": "rollup", "result": "singleton", "weight": 0.0},
				{"id": "window", "result": "present", "weight": 0.0},
				{"id": "coverage", "result": "skipped_l5_disabled", "weight": 0.0}
			],
			"flow": {
				"family": "path",
				"origins": ["external:param_hint"],
				"via": [],
				"guards": [],
				"hops": [
					{"line": 3, "kind": "param", "name": "fileName"},
					{"line": 4, "kind": "sink", "name": "fs.readFile"}
				],
				"truncated": false,
				"heuristic": "param_hint",
				"sinks": [4, 8, 12, 16]
			}
		}
	}`,
}

// refusedR1 is the agent's output for a file whose group would have its anchor's line under
// another check's CWE-23 row (R1): the line collapse drops the CWE-22 row there, so the agent
// refuses the group and sends its members' own rows. Descriptions, check lists and flow hops
// are left out: a merge within one agent reads none of them.
var refusedR1 = []string{
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 8,
		"line_end": 8,
		"check_id": "cwe.input_validation.path_traversal",
		"code_snippet": "8:   fs.readFile(fileName, cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {
			"status": "suspicious",
			"confidence": 0.5,
			"flow": {
				"family": "path",
				"origins": ["external:param_hint"],
				"heuristic": "param_hint"
			}
		}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 12,
		"line_end": 12,
		"check_id": "cwe.input_validation.path_traversal",
		"code_snippet": "12:   fs.readFile(filePath, cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {
			"status": "suspicious",
			"confidence": 0.5,
			"flow": {
				"family": "path",
				"origins": ["external:param_hint"],
				"heuristic": "param_hint"
			}
		}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-23",
		"title": "Path Equivalence: URL-encoded directory traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 4,
		"line_end": 4,
		"check_id": "cwe.path_eq.cwe_23",
		"code_snippet": "4:   fs.readFile(fileName + \"/..%2fone.txt\", cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {"status": "suspicious", "confidence": 0.5}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 8,
		"line_end": 12,
		"provenance": "catalog_rollup",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"is_rollup": true,
		"instance_count": 2,
		"validation": {"status": "suspicious", "confidence": 0.5}
	}`,
}

// refusedR2 is the agent's output for a file with CWE-23 rows at two member lines, rolled up
// under a CWE-23 parent at the anchor's line (R2): the group is refused, as for refusedR1.
var refusedR2 = []string{
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 12,
		"line_end": 12,
		"check_id": "cwe.input_validation.path_traversal",
		"code_snippet": "12:   fs.readFile(filePath, cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {
			"status": "suspicious",
			"confidence": 0.5,
			"flow": {
				"family": "path",
				"origins": ["external:param_hint"],
				"heuristic": "param_hint"
			}
		}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 16,
		"line_end": 16,
		"check_id": "cwe.input_validation.path_traversal",
		"code_snippet": "16:   fs.readFile(filePath, cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {
			"status": "suspicious",
			"confidence": 0.5,
			"flow": {
				"family": "path",
				"origins": ["external:param_hint"],
				"heuristic": "param_hint"
			}
		}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-23",
		"title": "Path Equivalence: URL-encoded directory traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 4,
		"line_end": 4,
		"check_id": "cwe.path_eq.cwe_23",
		"code_snippet": "4:   fs.readFile(fileName + \"/..%2fone.txt\", cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {"status": "suspicious", "confidence": 0.5}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-23",
		"title": "Path Equivalence: URL-encoded directory traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 8,
		"line_end": 8,
		"check_id": "cwe.path_eq.cwe_23",
		"code_snippet": "8:   fs.readFile(fileName + \"/..%2ftwo.txt\", cb);",
		"provenance": "skill",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"validation": {"status": "suspicious", "confidence": 0.5}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-22",
		"title": "Potential path traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 12,
		"line_end": 16,
		"provenance": "catalog_rollup",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"is_rollup": true,
		"instance_count": 2,
		"validation": {"status": "suspicious", "confidence": 0.5}
	}`,
	`{
		"agent_type": "cwe",
		"severity": "high",
		"category": "CWE-23",
		"title": "Path Equivalence: URL-encoded directory traversal",
		"file_path": "/scan/src/reader.js",
		"line_start": 4,
		"line_end": 8,
		"provenance": "catalog_rollup",
		"validation_status": "suspicious",
		"validation_confidence": 0.5,
		"is_rollup": true,
		"instance_count": 2,
		"validation": {"status": "suspicious", "confidence": 0.5}
	}`,
}

// llmRow0104 is another agent's LLM row at the group's anchor line, more severe than the group.
var llmRow0104 = []string{
	`{
		"agent_type": "asvs",
		"severity": "critical",
		"category": "CWE-22",
		"title": "Externally controlled path in readOne",
		"description": "model says",
		"file_path": "/scan/src/reader.js",
		"line_start": 4,
		"line_end": 4,
		"check_id": "",
		"code_snippet": "4:   fs.readFile(fileName, cb);",
		"provenance": "llm"
	}`,
}

// pluginRow0104 is another agent's deterministic row at the group's anchor line.
var pluginRow0104 = []string{
	`{
		"agent_type": "opengrep",
		"severity": "high",
		"category": "CWE-22",
		"title": "Attacker-controlled data flows into a filesystem call",
		"description": "x",
		"file_path": "/scan/src/reader.js",
		"line_start": 4,
		"line_end": 4,
		"check_id": "vulture-js-path-traversal",
		"code_snippet": "fs.readFile(fileName, cb);",
		"provenance": "opengrep"
	}`,
}

// unrelatedRow0104 is another agent's row of an unrelated CWE at a member line of the group.
var unrelatedRow0104 = []string{
	`{
		"agent_type": "xss",
		"severity": "medium",
		"category": "CWE-79",
		"title": "Reflected output",
		"file_path": "/scan/src/reader.js",
		"line_start": 8,
		"line_end": 8,
		"check_id": "xss.reflected",
		"code_snippet": "8:   fs.readFile(fileName, cb);",
		"provenance": "skill"
	}`,
}

// findings0104 decodes rows as the drain receives them and fingerprints each as it does.
func findings0104(t *testing.T, rows ...[]string) []model.Finding {
	t.Helper()
	var all []string
	for _, r := range rows {
		all = append(all, r...)
	}
	var fs []model.Finding
	if err := json.Unmarshal([]byte("["+strings.Join(all, ",")+"]"), &fs); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for i := range fs {
		fs[i].Fingerprint = fingerprint0104(fs[i])
	}
	return fs
}

// fingerprint0104 is the drain's fingerprint of a row (a rollup parent's is its own).
func fingerprint0104(f model.Finding) string {
	agent := f.AgentType
	if f.IsRollup {
		agent = "rollup-parent"
	}
	return generateFingerprint(f.Title, f.FilePath, f.Category, agent)
}

// flow0104 is a row's validation.flow, nil when it has none.
func flow0104(f model.Finding) map[string]interface{} {
	flow, _ := f.Validation["flow"].(map[string]interface{})
	return flow
}

// site0104 names a persisted row: its agent, CWE, line and status, whether it is a rollup
// parent, and the member sink lines it stands for.
func site0104(f model.Finding) string {
	s := fmt.Sprintf("%s %s@%d %s", f.AgentType, f.Category, f.LineStart, f.ValidationStatus)
	if f.IsRollup {
		s += " rollup"
	}
	if sinks, ok := flow0104(f)["sinks"]; ok {
		s += fmt.Sprintf(" sinks=%v", sinks)
	}
	return s
}

// persisted0104 merges rows as the drain does and names every row it keeps, sorted.
func persisted0104(t *testing.T, rows ...[]string) []string {
	t.Helper()
	kept := dedupCrossAgentDetailed(findings0104(t, rows...), root0104).kept
	sites := make([]string, 0, len(kept))
	for _, f := range kept {
		sites = append(sites, site0104(f))
	}
	sort.Strings(sites)
	return sites
}

// Test0104GroupRowSinksSurviveDedup is G19 (c): the group row goes through the cross-agent
// merge with its whole validation.flow, sinks included, alone and beside another agent's row
// of an unrelated CWE at a member line.
func Test0104GroupRowSinksSurviveDedup(t *testing.T) {
	want := flow0104(findings0104(t, group0104)[0])
	cases := map[string][][]string{
		"alone":                   {group0104},
		"beside an unrelated row": {group0104, unrelatedRow0104},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			kept := dedupCrossAgentDetailed(findings0104(t, rows...), root0104).kept
			if got := flow0104(kept[0]); !reflect.DeepEqual(got, want) {
				t.Fatalf("flow after the merge = %v, want %v", got, want)
			}
			if got := persisted0104(t, rows...)[0]; got != "cwe CWE-22@4 suspicious sinks=[4 8 12 16]" {
				t.Fatalf("persisted group row = %q", got)
			}
		})
	}
}

// Test0104RefusedGroupsPersistTheUngroupedSet pins R1 and R2: the agent refuses both groups,
// so it sends no row standing for others, and the merge persists exactly the set it persisted
// before rows were grouped.
func Test0104RefusedGroupsPersistTheUngroupedSet(t *testing.T) {
	cases := []struct {
		name string
		rows []string
		want []string
	}{
		{"R1: a CWE-23 row at the anchor line", refusedR1, []string{
			"cwe CWE-22@12 suspicious",
			"cwe CWE-22@8 suspicious rollup",
			"cwe CWE-23@4 suspicious",
		}},
		{"R2: a CWE-23 rollup parent at the anchor line", refusedR2, []string{
			"cwe CWE-22@12 suspicious rollup",
			"cwe CWE-22@16 suspicious",
			"cwe CWE-23@4 suspicious rollup",
			"cwe CWE-23@8 suspicious",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertUngrouped0104(t, findings0104(t, tc.rows))
			if got := persisted0104(t, tc.rows); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("persisted %v, want %v", got, tc.want)
			}
		})
	}
}

// assertUngrouped0104 fails when any row stands for other sink lines.
func assertUngrouped0104(t *testing.T, fs []model.Finding) {
	t.Helper()
	for _, f := range fs {
		if _, ok := flow0104(f)["sinks"]; ok {
			t.Fatalf("the agent sent a group row at %s@%d", f.Category, f.LineStart)
		}
	}
}

// Test0104OtherAgentsLLMRowEvictsTheGroup pins R3, accepted as OD-2 effect (f): another
// agent's LLM row, more severe than the group, takes the anchor line's key, so the group row
// and with it every member's line leave the persisted set. The lineage of those lines follows
// the model from scan to scan.
func Test0104OtherAgentsLLMRowEvictsTheGroup(t *testing.T) {
	want := []string{"asvs CWE-22@4 high_confidence"}
	if got := persisted0104(t, group0104, llmRow0104); !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted %v, want %v", got, want)
	}
}

// Test0104CorroborationLiftsEveryMember pins R4, accepted as OD-2 effect (g): another
// agent's row at the anchor line corroborates the group row, so the lifted status stands for
// every member's line, not the anchor's alone.
func Test0104CorroborationLiftsEveryMember(t *testing.T) {
	kept := dedupCrossAgentDetailed(findings0104(t, group0104, pluginRow0104), root0104).kept
	want := []string{"cwe CWE-22@4 high_confidence sinks=[4 8 12 16]"}
	if got := persisted0104(t, group0104, pluginRow0104); !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted %v, want %v", got, want)
	}
	if got := kept[0].CrossAgentOrigins; !reflect.DeepEqual(got, []string{"opengrep"}) {
		t.Fatalf("cross-agent origins = %v, want [opengrep]", got)
	}
}
