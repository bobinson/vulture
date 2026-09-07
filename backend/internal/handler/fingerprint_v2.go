package handler

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/vulture/backend/internal/model"
)

// Feature 0079 A3: a finding identity the LLM tier can keep across runs.
//
// generateFingerprint (v1) hashes title|path|category|agent. The title is the
// one field the LLM tier rephrases every run. Measured across three identical
// runs of one target: deterministic fingerprints 656 of 658 common to all
// three, LLM fingerprints 2 of ~113 — so 105 of run 2's 124 LLM findings were
// reported NEW despite existing in run 1.
//
// Corroborated on real accumulated data rather than inferred: max(ref_number)
// = 26,714 across 5,109 surviving lineages, roughly five-fold churn, with 1,320
// rows marked `regression` by a title that happened to recur.
//
// The two obvious single edits pull OPPOSITE ways, measured on the same data:
//
//	+ line_start : deterministic distinct 658 -> 838, LLM common 2 -> 0
//	- title      : LLM common 2 -> 29,          deterministic 658 -> 544
//
// Neither fixes both tiers, and a perfect title-free key still caps at 29/113
// because (path, category, agent) alone is only ~48% reproducible. Only a
// stable per-detector identity satisfies both — check_id, which A2 now
// persists. That is why A3 lands last in this feature and not first.

const (
	identityOff     = "off"
	identityObserve = "observe"
	identityEnforce = "enforce"
)

// findingIdentityMode reads VULTURE_FINDING_IDENTITY at call time.
//
// Default OFF. v2 is computed and stored but nothing reads it until an operator
// opts in, because changing which fingerprint LINEAGE resolves on is a one-way
// door for stored triage state.
func findingIdentityMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("VULTURE_FINDING_IDENTITY"))) {
	case "observe":
		return "observe"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

// fingerprintV2 is the stable identity: per-detector where one exists, and
// deployment-invariant either way.
//
// Differences from v1, each deliberate:
//
//   - check_id leads. Where a detector declares one, the identity does not
//     depend on the model's phrasing at all — a rephrased title yields the same
//     fingerprint, which is the entire point.
//   - the path is canonicalised against the source root. v1 hashes the raw
//     path, and git ingest writes to /tmp/vulture-sources/<sha+time.Now()>/run-<id>/
//     — a FRESH directory on every ingest — so a v1 fingerprint for a git source
//     never matches its own history.
//   - the title is retained ONLY as the fallback discriminant when no check_id
//     exists. Dropping it outright collapsed deterministic distinct counts from
//     658 to 544, because a per-skill constant title is what separates two
//     skills firing at the same file and category.
//   - line_start is deliberately NOT hashed, matching v1. The omission is
//     documented in FindingsTable.tsx and depended on by the plugin contract:
//     the fingerprint is intentionally shared across rows of one lineage class.
//     Adding it took the LLM tier's cross-run intersection from 2 to 0.
func fingerprintV2(f model.Finding, sourceRoot string) string {
	agent := strings.ToLower(strings.TrimSpace(f.AgentType))
	if f.IsRollup {
		// v1 uses the literal "rollup-parent" as its fourth component, worth +68
		// distinct fingerprints on the reference target. Keep the distinction.
		agent = "rollup-parent"
	}
	identity := strings.TrimSpace(f.CheckID)
	if identity == "" {
		identity = "title:" + strings.ToLower(strings.TrimSpace(f.Title))
	}
	norm := fmt.Sprintf("v2|%s|%s|%s|%s",
		identity,
		canonicalFindingPath(strings.TrimSpace(f.FilePath), sourceRoot),
		strings.ToLower(strings.TrimSpace(f.Category)),
		agent)
	h := sha256.Sum256([]byte(norm))
	return fmt.Sprintf("%x", h[:16])
}

// stampIdentity fills FingerprintV2 (and, under enforce, swaps the resolution
// order) for a batch of findings.
//
// LegacyFingerprint carries the v1 value forward in memory so lineage can match
// on EITHER. It is json:"-" and appears in no column list, so it never reaches
// a client or a database — it exists purely so the flip is lossless for the
// 5,109 stored lineage rows whose UNIQUE key is the v1 fingerprint.
func stampIdentity(findings []model.Finding, sourceRoot string) {
	if findingIdentityMode() == identityOff {
		return
	}
	for i := range findings {
		v2 := fingerprintV2(findings[i], sourceRoot)
		findings[i].FingerprintV2 = v2
		if findingIdentityMode() == identityEnforce {
			// Keep the v1 value reachable: detectFixed marks any absent
			// fingerprint FIXED, so without this the first enforce run would
			// mark every historical finding fixed and mint a new VLT ref for
			// each one — a one-time destruction of triage state.
			findings[i].LegacyFingerprint = findings[i].Fingerprint
			findings[i].Fingerprint = v2
		}
	}
}
