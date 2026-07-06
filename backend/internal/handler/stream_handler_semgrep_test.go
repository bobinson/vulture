package handler

// Feature 0058 T4/T5 — cross-agent dedup + provenance + CWE-taxonomy
// reconciliation between the CWE agent (skills/signatures) and the
// Semgrep plugin (LLD R5 / R5b / R6, P3a/P3b).
//
// Pinned contracts:
//
//  1. deduplicateCrossAgent(findings []model.Finding) []model.Finding
//     (existing, this package):
//       - exact overlap (same CWE category + file + line) from "cwe"
//         and "semgrep" reports ONCE; the survivor records both agents
//         (AgentType + CrossAgentOrigins cover {"cwe","semgrep"}) and
//         a non-empty Provenance survives the merge.
//       - a semgrep-only finding (no counterpart site) is retained
//         unchanged (net-new augmentation).
//       - when the merged pair's richer member carries
//         Provenance "semgrep", the survivor keeps it (T5/R6).
//
//  2. NEW API (GREEN implements in package handler, file
//     cwe_taxonomy.go):
//
//         func canonicalCWEGroup(category string) string
//
//     Returns a stable group id shared by taxonomically-related CWE
//     ids (O(1) map lookup, cyclomatic complexity < 5). Unrelated or
//     non-CWE categories return the input unchanged. Families pinned:
//       path-traversal        {CWE-22, CWE-23, CWE-36, CWE-73}
//       os-command-injection  {CWE-77, CWE-78, CWE-88}
//       sql-injection         {CWE-89, CWE-943}
//       xss                   {CWE-79, CWE-80}
//     R5b: deduplicateCrossAgent reconciles same-site findings whose
//     categories fall in the SAME family (e.g. skill CWE-22 vs semgrep
//     CWE-73) into ONE corroborated finding; different families at the
//     same site (CWE-89 vs CWE-79) do NOT merge.

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// semgrepSiteFinding builds a finding at a fixed site for dedup tests.
func semgrepSiteFinding(agentType, category, title, filePath string, line int) model.Finding {
	return model.Finding{
		ID:        "f-" + agentType + "-" + category,
		AgentType: agentType,
		Severity:  model.SeverityHigh,
		Category:  category,
		Title:     title,
		FilePath:  filePath,
		LineStart: line,
		LineEnd:   line,
	}
}

// agentsRecordedBy returns the set of agent types the survivor records:
// its own AgentType plus every CrossAgentOrigins entry.
func agentsRecordedBy(f model.Finding) map[string]bool {
	set := map[string]bool{f.AgentType: true}
	for _, a := range f.CrossAgentOrigins {
		set[a] = true
	}
	return set
}

// --- T4a: exact overlap → ONE finding, both agents recorded, provenance survives ---

func TestDeduplicateCrossAgent_SemgrepExactOverlap_ReportsOnce(t *testing.T) {
	skill := semgrepSiteFinding("cwe", "CWE-89", "SQL injection detected", "src/db.py", 42)
	sg := semgrepSiteFinding("semgrep", "CWE-89", "Tainted input flows into SQL query", "src/db.py", 42)
	sg.Provenance = "semgrep"
	sg.CodeSnippet = `cursor.execute("SELECT * FROM users WHERE id = " + uid)` // richer member

	out := deduplicateCrossAgent([]model.Finding{skill, sg})

	if len(out) != 1 {
		t.Fatalf("same CWE+file+line from cwe and semgrep must report ONCE, got %d findings", len(out))
	}
	recorded := agentsRecordedBy(out[0])
	if !recorded["cwe"] || !recorded["semgrep"] {
		t.Errorf("survivor must record both agents via AgentType+CrossAgentOrigins; got agent=%q origins=%v",
			out[0].AgentType, out[0].CrossAgentOrigins)
	}
	if out[0].Provenance == "" {
		t.Error("a non-empty Provenance must survive the cross-agent merge")
	}
}

// --- T4b: semgrep-only finding → retained unchanged (net-new) ---

func TestDeduplicateCrossAgent_SemgrepOnly_RetainedAsNetNew(t *testing.T) {
	skill := semgrepSiteFinding("cwe", "CWE-798", "Hardcoded credentials", "src/config.py", 7)
	sgOnly := semgrepSiteFinding("semgrep", "CWE-918", "SSRF via unvalidated URL", "src/fetch.py", 88)
	sgOnly.Provenance = "semgrep"

	out := deduplicateCrossAgent([]model.Finding{skill, sgOnly})

	if len(out) != 2 {
		t.Fatalf("distinct sites must both be retained, got %d findings", len(out))
	}
	var got *model.Finding
	for i := range out {
		if out[i].AgentType == "semgrep" {
			got = &out[i]
		}
	}
	if got == nil {
		t.Fatal("semgrep-only finding must be retained (net-new augmentation)")
	}
	if got.Provenance != "semgrep" {
		t.Errorf("net-new semgrep finding Provenance = %q, want \"semgrep\"", got.Provenance)
	}
	if len(got.CrossAgentOrigins) != 0 {
		t.Errorf("net-new finding must have no CrossAgentOrigins, got %v", got.CrossAgentOrigins)
	}
}

// --- R5b: canonicalCWEGroup families ---

func assertSameGroup(t *testing.T, family string, ids []string) {
	t.Helper()
	group := canonicalCWEGroup(ids[0])
	if group == "" {
		t.Fatalf("%s: canonicalCWEGroup(%q) must be non-empty", family, ids[0])
	}
	for _, id := range ids[1:] {
		if g := canonicalCWEGroup(id); g != group {
			t.Errorf("%s: canonicalCWEGroup(%q)=%q, want same group as %q (%q)", family, id, g, ids[0], group)
		}
	}
}

func TestCanonicalCWEGroup_PathTraversalFamily(t *testing.T) {
	assertSameGroup(t, "path-traversal", []string{"CWE-22", "CWE-23", "CWE-36", "CWE-73"})
}

func TestCanonicalCWEGroup_OSCommandInjectionFamily(t *testing.T) {
	assertSameGroup(t, "os-command-injection", []string{"CWE-77", "CWE-78", "CWE-88"})
}

func TestCanonicalCWEGroup_SQLInjectionFamily(t *testing.T) {
	assertSameGroup(t, "sql-injection", []string{"CWE-89", "CWE-943"})
}

func TestCanonicalCWEGroup_XSSFamily(t *testing.T) {
	assertSameGroup(t, "xss", []string{"CWE-79", "CWE-80"})
}

func TestCanonicalCWEGroup_DifferentFamilies_DistinctGroups(t *testing.T) {
	groups := map[string]string{
		"sql-injection":        canonicalCWEGroup("CWE-89"),
		"xss":                  canonicalCWEGroup("CWE-79"),
		"path-traversal":       canonicalCWEGroup("CWE-22"),
		"os-command-injection": canonicalCWEGroup("CWE-78"),
	}
	seen := map[string]string{}
	for family, g := range groups {
		if other, dup := seen[g]; dup {
			t.Errorf("families %s and %s must have distinct group ids, both got %q", family, other, g)
		}
		seen[g] = family
	}
}

func TestCanonicalCWEGroup_UnrelatedOrNonCWE_ReturnedUnchanged(t *testing.T) {
	for _, in := range []string{"CWE-798", "A03:2021 Injection", "chaos.retry", ""} {
		if got := canonicalCWEGroup(in); got != in {
			t.Errorf("canonicalCWEGroup(%q) = %q, want input unchanged", in, got)
		}
	}
}

// --- R5b: taxonomy reconciliation inside deduplicateCrossAgent ---

func TestDeduplicateCrossAgent_TaxonomyRelatedCWEs_ReconcileToOne(t *testing.T) {
	skill := semgrepSiteFinding("cwe", "CWE-22", "Path traversal", "src/files.py", 17)
	sg := semgrepSiteFinding("semgrep", "CWE-73", "External control of file name or path", "src/files.py", 17)
	sg.Provenance = "semgrep"

	out := deduplicateCrossAgent([]model.Finding{skill, sg})

	if len(out) != 1 {
		t.Fatalf("taxonomically-related CWE-22 (cwe) + CWE-73 (semgrep) at the same site must reconcile to ONE corroborated finding (R5b), got %d", len(out))
	}
	recorded := agentsRecordedBy(out[0])
	if !recorded["cwe"] || !recorded["semgrep"] {
		t.Errorf("reconciled finding must record both agents; got agent=%q origins=%v",
			out[0].AgentType, out[0].CrossAgentOrigins)
	}
}

func TestDeduplicateCrossAgent_DifferentFamilies_DoNotMerge(t *testing.T) {
	skill := semgrepSiteFinding("cwe", "CWE-89", "SQL injection", "src/view.py", 30)
	sg := semgrepSiteFinding("semgrep", "CWE-79", "Reflected XSS", "src/view.py", 30)

	out := deduplicateCrossAgent([]model.Finding{skill, sg})

	if len(out) != 2 {
		t.Fatalf("CWE-89 and CWE-79 at the same site are different families and must NOT merge, got %d findings", len(out))
	}
}

// --- T5: provenance flows through the merge (richer member wins) ---

func TestDeduplicateCrossAgent_MergeKeepsRicherMemberProvenanceSemgrep(t *testing.T) {
	skill := semgrepSiteFinding("cwe", "CWE-78", "OS command injection", "src/run.py", 55)
	sg := semgrepSiteFinding("semgrep", "CWE-78", "Tainted input reaches subprocess call", "src/run.py", 55)
	sg.Provenance = "semgrep"
	// Make the semgrep member unambiguously richer per findingDetailScore.
	sg.CodeSnippet = "subprocess.run(cmd, shell=True)"
	sg.References = []string{"https://cwe.mitre.org/data/definitions/78.html"}
	sg.CheckID = "vulture.taint.os-command-injection"

	out := deduplicateCrossAgent([]model.Finding{skill, sg})

	if len(out) != 1 {
		t.Fatalf("expected one merged finding, got %d", len(out))
	}
	if out[0].Provenance != "semgrep" {
		t.Errorf("merged finding must keep the richer member's Provenance \"semgrep\", got %q", out[0].Provenance)
	}
}
