package handler

import (
	"crypto/sha256"
	"fmt"
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

const ()

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

// stampIdentity fills FingerprintV2 for a batch of findings.
//
// Always: computing v2 is additive and reversible — a row keeps whatever v2 it
// has, and lineage matching tries v2 then falls back to the v1 fingerprint, so
// a row stamped by an older build still resolves. `fingerprint` itself is never
// rewritten; that would move the key stored triage hangs on.
func stampIdentity(findings []model.Finding, sourceRoot string) {
	for i := range findings {
		findings[i].FingerprintV2 = fingerprintV2(findings[i], sourceRoot)
	}
}
