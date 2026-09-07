package handler

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0079 A1 + A4.
//
// A1: the two tiers emit systematically different file_path forms — measured
// 838 deterministic rows ABSOLUTE and 132 LLM rows RELATIVE, zero exceptions in
// either direction, on both SQLite and Postgres. crossAgentKey interpolates
// f.FilePath raw, so an LLM row can never collide with a deterministic one.
// Measured: 0 llm-vs-det collisions today, 24 once the path is normalised.
// VULTURE_DEDUP_PREFER_DETERMINISTIC is therefore VACUOUS — the collision it
// exists to arbitrate cannot occur.
//
// The key is canonicalised, NOT the stored value. file_path does two
// incompatible jobs: display/resolution (llm_judge does a bare os.stat and
// needs absolute) and identity (must be deployment-invariant). Git ingest
// writes to /tmp/vulture-sources/<sha+time.Now()>/run-<id>/, a FRESH directory
// every ingest, so absolute paths are not invariant even on one machine.
// Key-only also leaves generateFingerprint untouched, which is what dissolves
// the A1<->A3 coupling.
//
// A4: normalising surfaces 24 collisions, of which 2 are CROSS-WEAKNESS and
// must NOT merge — e.g. A01-broken-access-control at profileImageUrlUpload.ts:19
// holds Open Redirect (CWE-601) and SSRF (CWE-918), one tainted variable and two
// genuinely different weaknesses. Merging them LOSES a finding, so the veto is a
// hard prerequisite of enabling A1's enforce mode.

func pf(agent, cat, path, title string, line int) model.Finding {
	return model.Finding{AgentType: agent, Category: cat, FilePath: path, Title: title, LineStart: line}
}

// A1-T1 — NON-VACUITY: at least one path is actually rewritten.
func TestPathCanonActuallyRewrites(t *testing.T) {
	root := "/home/user/src/juice-shop"
	got := canonicalFindingPath("/home/user/src/juice-shop/routes/basket.ts", root)
	if got != "routes/basket.ts" {
		t.Fatalf("absolute path not canonicalised: got %q", got)
	}
	if canonicalFindingPath("routes/basket.ts", root) != "routes/basket.ts" {
		t.Error("an already-relative path must pass through unchanged")
	}
}

// A1-T2 — the two tier forms must resolve to the SAME key.
func TestBothTierPathFormsProduceOneKey(t *testing.T) {
	root := "/home/user/src/juice-shop"
	det := pf("cwe", "CWE-89", "/home/user/src/juice-shop/routes/login.ts", "SQL injection", 34)
	llm := pf("cwe", "CWE-89", "routes/login.ts", "SQL Injection in Login Query", 34)

	if crossAgentKeyWithRoot(det, "") == crossAgentKeyWithRoot(llm, "") {
		t.Fatal("precondition failed: the raw forms should differ today")
	}
	if crossAgentKeyWithRoot(det, root) != crossAgentKeyWithRoot(llm, root) {
		t.Errorf("canonicalised keys still differ:\n  det=%s\n  llm=%s",
			crossAgentKeyWithRoot(det, root), crossAgentKeyWithRoot(llm, root))
	}
}

// A1-T3 — the root must match on a PATH BOUNDARY, never a string prefix.
// _normalize_dedup_path has this bug today: root /x/repo eats /x/repo-backup.
func TestPathCanonRespectsPathBoundaries(t *testing.T) {
	got := canonicalFindingPath("/x/repo-backup/a.py", "/x/repo")
	if got == "-backup/a.py" {
		t.Fatal("string-prefix stripping produced '-backup/a.py'; the root must " +
			"match on a path boundary")
	}
	if got != "/x/repo-backup/a.py" {
		t.Errorf("a path outside the root must be left alone, got %q", got)
	}
}

// A1-T4 — a finding AT the root keeps a location token. ~25 SSDF/SOC2
// repo-level rows use file_path == source_path; mapping them to "" would put
// them all on one key and destroy them.
func TestRootItselfKeepsALocationToken(t *testing.T) {
	got := canonicalFindingPath("/home/user/src/app", "/home/user/src/app")
	if got == "" {
		t.Fatal("the root itself mapped to the empty string: every repo-level " +
			"finding would collapse onto one key")
	}
	if got != "." {
		t.Errorf("expected \".\" for the root itself, got %q", got)
	}
}

// A1-T5 — an empty root disables canonicalisation entirely (the replay path).
func TestEmptyRootIsIdentity(t *testing.T) {
	for _, p := range []string{"/abs/a.go", "rel/a.go", "."} {
		if got := canonicalFindingPath(p, ""); got != p {
			t.Errorf("empty root must be identity for %q, got %q", p, got)
		}
	}
}

// A4-T1 — NON-VACUITY: the veto must split a REAL collision.
func TestCoarseCategoryVetoSplitsTheMeasuredFalseCollision(t *testing.T) {
	root := "/src/juice-shop"
	redirect := pf("owasp", "A01-broken-access-control",
		"/src/juice-shop/routes/profileImageUrlUpload.ts", "Open redirect vulnerability", 19)
	ssrf := pf("owasp", "A01-broken-access-control",
		"routes/profileImageUrlUpload.ts", "Server-Side Request Forgery in profile image upload", 19)

	if crossAgentKeyWithRoot(redirect, root) == crossAgentKeyWithRoot(ssrf, root) {
		t.Fatal("two DIFFERENT weaknesses at one line share a key: merging them " +
			"loses a real finding")
	}
}

// A4-T2 — a genuine duplicate must STILL merge. A veto that splits everything
// is as wrong as one that splits nothing.
func TestGenuineDuplicatesStillMerge(t *testing.T) {
	root := "/src/juice-shop"
	skill := pf("cwe", "CWE-89", "/src/juice-shop/routes/login.ts", "SQL injection via string interpolation", 34)
	llm := pf("cwe", "CWE-89", "routes/login.ts", "SQL Injection in Login Query", 34)
	if crossAgentKeyWithRoot(skill, root) != crossAgentKeyWithRoot(llm, root) {
		t.Error("the same weakness reported twice must still merge")
	}
}

// A4-T3 — CWE-keyed rows must be BYTE-IDENTICAL to today when canon is off, so
// the veto cannot regress the fine-grained path.
func TestFineGrainedKeysAreUnchangedWithoutCanon(t *testing.T) {
	f := pf("cwe", "CWE-79", "/abs/a.ts", "XSS", 10)
	if crossAgentKeyWithRoot(f, "") != crossAgentKey(f) {
		t.Errorf("with canon off the key must equal the legacy key:\n  new=%s\n  old=%s",
			crossAgentKeyWithRoot(f, ""), crossAgentKey(f))
	}
}

// A4-T4 — "coarse" must be decided by the SHAPE of the category, never by a
// hardcoded agent list, or every new agent needs an edit.
func TestCoarsenessIsDecidedByShapeNotAgentName(t *testing.T) {
	fine := []string{"CWE-79", "CWE-1336", "ASVS-V8.2.1"}
	coarse := []string{"PW", "CC6", "A01-broken-access-control", "retry", "asvs_requirements"}
	for _, c := range fine {
		if !isFineGrainedCategory(c) {
			t.Errorf("%q should be fine-grained", c)
		}
	}
	for _, c := range coarse {
		if isFineGrainedCategory(c) {
			t.Errorf("%q should be coarse", c)
		}
	}
}

// A1-T6 — the DEFAULT is off, pinned here.
//
// env.example states `VULTURE_FINDING_PATH_CANON=off`, and the Python
// env-defaults conformance guard cannot verify it: its Go resolver matches only
// bool and int literals, so a string-valued mode switch resolves to nothing.
// Widening that resolver was tried and rejected — several string literals per
// function make its sole-candidate rule ambiguous, breaking eight of its own
// tests. So the guarantee lives here instead, on the Go side that owns it.
func TestPathCanonDefaultsToOff(t *testing.T) {
	t.Setenv("VULTURE_FINDING_PATH_CANON", "")
	if got := pathCanonMode(); got != "off" {
		t.Fatalf("default must be off (observe costs +114%% on every audit), got %q", got)
	}
	for in, want := range map[string]string{
		"observe": "observe", "enforce": "enforce",
		"OBSERVE": "observe", " enforce ": "enforce",
		"nonsense": "off", "true": "off",
	} {
		t.Setenv("VULTURE_FINDING_PATH_CANON", in)
		if got := pathCanonMode(); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
