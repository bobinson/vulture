package handler

import (
	"log"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/model"
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

const (
	pathCanonOff     = "off"
	pathCanonObserve = "observe"
	pathCanonEnforce = "enforce"
)

// pathCanonMode reads VULTURE_FINDING_PATH_CANON at call time.
//
// Default OFF, deliberately, against the plan's original "observe by default".
// `observe` runs the dedup a second time to report the delta, and that was
// benchmarked at +38.2ms over a 33.4ms baseline at 50k findings — a 114%
// increase that every audit would pay forever. An opt-in measurement mode is
// worth having; a default-on one is not.
func pathCanonMode() string {
	// String literals, not the named constants above: the 0078 env-defaults
	// conformance guard resolves a Go switch's default by reading the literals
	// in the enclosing function, and a constant reference is invisible to it.
	// Keeping the default legible to that check is worth more than the
	// indirection.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("VULTURE_FINDING_PATH_CANON"))) {
	case "observe":
		return "observe"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

// canonicalFindingPath maps a finding path to its source-root-relative form.
//
// An empty root is identity, which is how the replay path and every existing
// test keep byte-identical behaviour.
func canonicalFindingPath(filePath, root string) string {
	if root == "" || filePath == "" {
		return filePath
	}
	cleanRoot := strings.TrimRight(path.Clean(root), "/")
	cleanPath := path.Clean(filePath)
	if cleanPath == cleanRoot {
		// A finding ON the root itself. ~25 SSDF/SOC2 repo-level rows use
		// file_path == source_path with line 1; mapping them to "" would put
		// every one of them on a single key and destroy all but one.
		return "."
	}
	// Path-BOUNDARY match, not a string prefix. _normalize_dedup_path has the
	// prefix bug today: root /x/repo turns /x/repo-backup/a.py into
	// "-backup/a.py". Requiring the separator makes that impossible.
	if strings.HasPrefix(cleanPath, cleanRoot+"/") {
		return strings.TrimPrefix(cleanPath, cleanRoot+"/")
	}
	// Outside the root: leave it absolute. Stripping the leading slash would
	// turn /etc/passwd into etc/passwd, which is harmless in a private key and
	// a real hazard anywhere it is rendered.
	return cleanPath
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

// weaknessVetoEnabled gates A4. Never flip this to false as a rollback: it is
// the only switch here whose false value can LOSE a finding, because it lets
// two different weaknesses at one line merge.
func weaknessVetoEnabled() bool {
	if v := strings.TrimSpace(os.Getenv("VULTURE_DEDUP_WEAKNESS_VETO")); v != "" {
		return config.EnvTruthy("VULTURE_DEDUP_WEAKNESS_VETO")
	}
	return true
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
	if !weaknessVetoEnabled() || isFineGrainedCategory(category) {
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

// logPathCanonDelta reports what `enforce` WOULD merge, without changing
// anything. This is the whole deliverable of `observe` mode.
//
// It splits the delta by collision class, because the classes carry different
// risk: det-vs-llm merges are the 22 genuine duplicates the feature exists to
// remove, while a cross-weakness pair is a finding that must NOT merge. An
// operator needs both numbers before flipping to enforce, not a single total.
func logPathCanonDelta(findings []model.Finding, root string) {
	rawKeys := make(map[string]int, len(findings))
	canonKeys := make(map[string][]int, len(findings))
	for i, f := range findings {
		rawKeys[crossAgentKeyWithRoot(f, "")]++
		k := crossAgentKeyWithRoot(f, root)
		canonKeys[k] = append(canonKeys[k], i)
	}
	var detLLM, detDet, llmLLM, coarseSplit int
	for _, idx := range canonKeys {
		if len(idx) < 2 {
			continue
		}
		llm, det := 0, 0
		for _, i := range idx {
			if isLLMProvenance(findings[i]) {
				llm++
			} else {
				det++
			}
		}
		switch {
		case llm > 0 && det > 0:
			detLLM++
		case det > 1:
			detDet++
		case llm > 1:
			llmLLM++
		}
	}
	// How many keys the coarse-category veto is currently holding apart. Zero
	// here with a non-zero det_llm count means the veto is not firing and the
	// cross-weakness merges are NOT being prevented.
	for _, f := range findings {
		if f.Category != "" && !isFineGrainedCategory(f.Category) {
			coarseSplit++
		}
	}
	log.Printf("[dedup] path_canon mode=observe raw_keys=%d canon_keys=%d "+
		"merges det_llm=%d det_det=%d llm_llm=%d coarse_rows_vetoed=%d",
		len(rawKeys), len(canonKeys), detLLM, detDet, llmLLM, coarseSplit)
}
