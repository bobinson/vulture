package handler

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0079 A3: a finding identity the LLM tier can actually keep.
//
// generateFingerprint hashes title|path|category|agent. The title is the one
// field the LLM tier rephrases every run, so measured across three identical
// runs: deterministic fingerprints 656 of 658 common to all three, LLM
// fingerprints 2 of ~113. 105 of run 2's 124 LLM findings were reported NEW
// despite existing in run 1.
//
// Corroborated on real accumulated data: max(ref_number)=26,714 across 5,109
// surviving lineages — roughly five-fold churn, with 1,320 rows marked
// `regression` by titles that happened to recur.
//
// The two obvious single edits pull OPPOSITE ways, measured on the same
// archives:
//   + line_start : deterministic distinct 658 -> 838, LLM common 2 -> 0
//   - title      : LLM common 2 -> 29,          deterministic 658 -> 544
// Only a stable per-detector identity satisfies both — check_id, which A2 now
// persists. That is why A3 lands last.

func fpF(agent, checkID, cat, path, title string, line int) model.Finding {
	return model.Finding{AgentType: agent, CheckID: checkID, Category: cat,
		FilePath: path, Title: title, LineStart: line}
}

// A3-T1 — the whole point: a rephrased title must NOT change the identity when
// a check_id is present.
func TestFingerprintV2SurvivesATitleRewrite(t *testing.T) {
	a := fpF("cwe", "cwe.injection.sql", "CWE-89", "routes/login.ts", "SQL injection via string interpolation", 34)
	b := fpF("cwe", "cwe.injection.sql", "CWE-89", "routes/login.ts", "SQL Injection in Login Query", 34)
	if fingerprintV2(a, "") != fingerprintV2(b, "") {
		t.Fatal("the same detector at the same site got two identities because the " +
			"model rephrased the title — this is the 5x lineage churn")
	}
}

// A3-T2 — but it must still SEPARATE genuinely different detectors, or the fix
// trades churn for collapse.
func TestFingerprintV2SeparatesDifferentDetectors(t *testing.T) {
	stored := fpF("xss", "xss.stored.db_render", "CWE-79", "h.ts", "Stored XSS", 138)
	reflected := fpF("xss", "xss.reflected.inner_html", "CWE-79", "h.ts", "Reflected XSS", 138)
	if fingerprintV2(stored, "") == fingerprintV2(reflected, "") {
		t.Fatal("two different detectors at one site collapsed to one identity")
	}
}

// A3-T3 — without a check_id it must fall back to today's inputs, so nothing
// regresses for a row that has none.
func TestFingerprintV2FallsBackWhenNoCheckID(t *testing.T) {
	f := fpF("chaos", "", "retry", "a.go", "Missing retry", 1)
	if fingerprintV2(f, "") == "" {
		t.Fatal("a finding without a check_id must still get an identity")
	}
	g := fpF("chaos", "", "retry", "a.go", "Missing retry entirely", 1)
	if fingerprintV2(f, "") == fingerprintV2(g, "") {
		t.Error("with no check_id the title must still discriminate, as it does today")
	}
}

// A3-T4 — v1 must be untouched. The whole migration story rests on the old
// value still being computable, so stored lineage rows keep matching.
func TestFingerprintV1IsUnchanged(t *testing.T) {
	got := generateFingerprint("SQL injection", "/abs/routes/login.ts", "CWE-89", "cwe")
	want := "4f5e4b41d13b1e30409e0302bc278a11" // measured, not invented: pins TODAY's value
	if got != want {
		t.Fatalf("v1 fingerprint changed: got %s want %s — every stored lineage row "+
			"and user label is keyed on this value", got, want)
	}
}

// A3-T5 — v2 is deployment-invariant where v1 is not. Git ingest writes to a
// fresh /tmp/vulture-sources/<sha+time>/run-<id>/ directory on EVERY ingest, so
// an absolute path makes v1 differ between two ingests of the same repo.
func TestFingerprintV2IsDeploymentInvariant(t *testing.T) {
	rootA := "/tmp/vulture-sources/aaa/run-1"
	rootB := "/tmp/vulture-sources/bbb/run-2"
	a := fpF("cwe", "cwe.injection.sql", "CWE-89", rootA+"/routes/login.ts", "SQL injection", 34)
	b := fpF("cwe", "cwe.injection.sql", "CWE-89", rootB+"/routes/login.ts", "SQL injection", 34)

	if generateFingerprint(a.Title, a.FilePath, a.Category, a.AgentType) ==
		generateFingerprint(b.Title, b.FilePath, b.Category, b.AgentType) {
		t.Fatal("precondition failed: v1 should differ across ingest dirs")
	}
	if fingerprintV2(a, rootA) != fingerprintV2(b, rootB) {
		t.Error("v2 must be invariant across ingest directories, or git sources " +
			"never match their own history")
	}
}

// A3-T6 — the rollup branch. The fourth v1 component is "rollup-parent", not
// the agent type, and it is worth +68 distinct fingerprints on the reference
// target. v2 must keep that distinction.
func TestFingerprintV2KeepsTheRollupDistinction(t *testing.T) {
	member := fpF("cwe", "cwe.x.y", "CWE-79", "a.ts", "XSS", 1)
	parent := member
	parent.IsRollup = true
	if fingerprintV2(member, "") == fingerprintV2(parent, "") {
		t.Error("a rollup parent must not share its member's identity")
	}
}

// A3-T9 — observe computes and stores, and changes nothing a consumer reads.
func TestObserveIsInert(t *testing.T) {
	f := fpF("cwe", "cwe.injection.sql", "CWE-89", "/root/a.ts", "SQLi", 1)
	f.Fingerprint = "original"
	batch := []model.Finding{f}
	stampIdentity(batch, "/root")

	if batch[0].Fingerprint != "original" {
		t.Error("observe must not move Fingerprint — nothing may resolve on v2 yet")
	}
	if batch[0].LegacyFingerprint != "" {
		t.Error("observe must not set LegacyFingerprint; there is nothing to bridge")
	}
	if batch[0].FingerprintV2 == "" {
		t.Error("observe must still COMPUTE v2, or the mode measures nothing")
	}
}
