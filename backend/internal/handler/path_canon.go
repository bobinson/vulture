package handler

import (
	"regexp"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/pathutil"
)

// Feature 0079 A1 + A4: one dedup identity for both finding tiers.
//
// The two tiers emit systematically different file_path forms. Measured on
// juice-shop, on BOTH backends: all 838 deterministic rows carry an ABSOLUTE
// path, all LLM rows a RELATIVE one, zero exceptions either way. Because
// crossAgentKey interpolates f.FilePath raw, an LLM row can never collide with a
// deterministic one — 0 such collisions today, 24 once the path is normalised.
//
// So VULTURE_DEDUP_PREFER_DETERMINISTIC, documented as 0076 re-anchoring's hard
// prerequisite, is VACUOUS: the collision it arbitrates cannot occur.
//
// SCOPE: the KEY is canonicalised, never the stored value. `file_path` does two
// incompatible jobs — display/resolution (llm_judge._file_signature does a bare
// os.stat and works only for absolute) and identity (must be deployment-
// invariant). No single string satisfies both, and git ingest writes to
// /tmp/vulture-sources/<sha+time.Now()>/run-<id>/ — a fresh directory on EVERY
// ingest — so absolute paths are not invariant even on one machine.
//
// Key-only also leaves generateFingerprint untouched, which is what dissolves
// the A1<->A3 coupling: no stored fingerprint moves, so no finding_lineage row
// is orphaned and no triage state is lost.

// canonicalFindingPath maps a finding path to its source-root-relative form.
//
// An empty root is identity, which is how the replay path and every existing
// test keep byte-identical behaviour.
//
// Feature 0091 moved the body to pathutil.RelToRoot without changing a byte of
// its behaviour: target identity has to strip the same kind of prefix from the
// same kind of path, and two copies of "what does it mean to be under this
// root" is how the two answers start disagreeing.
func canonicalFindingPath(filePath, root string) string {
	return pathutil.RelToRoot(filePath, root)
}

// fineGrainedCategory matches a category specific enough to identify ONE
// weakness on its own: a CWE id, or an ASVS requirement id.
var fineGrainedCategory = regexp.MustCompile(`^(?i)(CWE-\d{1,5}|(ASVS-)?V\d+(\.\d+){1,3})$`)

// isFineGrainedCategory reports whether a category names a single weakness.
//
// Decided by SHAPE, never by an agent list — a hardcoded list needs an edit for
// every new agent, and the whole point of A4 is that the hazard is not
// agent-specific. Coarse vocabularies that reach here: ssdf PO/PS/PW/RV, soc2
// CC6/CC7/CC8, chaos pattern names, owasp A0x-* ids, asvs "asvs_requirements".
func isFineGrainedCategory(category string) bool {
	return fineGrainedCategory.MatchString(strings.TrimSpace(category))
}

// crossAgentKeyWithRoot is crossAgentKey with the path canonicalised against
// root, plus the A4 coarse-category veto.
//
// root == "" reproduces crossAgentKey byte for byte, so every existing call site
// and test is unaffected.
func crossAgentKeyWithRoot(f model.Finding, root string) string {
	if root == "" {
		return crossAgentKey(f)
	}
	p := canonicalFindingPath(f.FilePath, root)
	cat := strings.TrimSpace(f.Category)
	if cat == "" {
		return strings.ToLower(strings.TrimSpace(f.Title)) + "|" + p + "|" + itoaInt(f.LineStart)
	}
	return "cat:" + canonicalCWEGroup(cat) + "|" + p + "|" + itoaInt(f.LineStart) +
		coarseCategorySuffix(cat, f.Title)
}

// coarseCategorySuffix appends a discriminant when the category is too blunt to
// identify a weakness by itself.
//
// Canonicalising the path surfaced 24 collisions, and 2 of them are
// CROSS-WEAKNESS: A01-broken-access-control at profileImageUrlUpload.ts:19
// holds Open Redirect (CWE-601) and SSRF (CWE-918) — one tainted variable,
// `const url = req.body.imageUrl`, and two genuinely different weaknesses.
// Merging them loses a real finding, and with the deterministic preference on
// the skill row wins and the SSRF row is DELETED.
//
// Splitting a key can only ADD rows, never lose one, and fine-grained (CWE-,
// ASVS-) keys are byte-identical because the suffix is empty for them.
func coarseCategorySuffix(category, title string) string {
	if isFineGrainedCategory(category) {
		return ""
	}
	return "|" + strings.ToLower(strings.TrimSpace(title))
}

// itoaInt avoids pulling strconv into the hot key path for one small int.
func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
