package handler

// Feature 0076 §5.5 / T4.1 / AC15 — the Go winner-selection guard.
//
// WHY THIS TEST EXISTS
//
// `deduplicateCrossAgent` (stream_handler.go:751) keeps exactly ONE row per
// `crossAgentKey` (:1013) and picks the keeper with `findingDetailScore`
// (:1027-1050). That score is severity-dominant (`severityRank(sev) * 10`)
// and has NO `Provenance` term, so an `llm` row that claims `critical` — or
// merely lists a long reference block — displaces the deterministic skill row
// at the same site. Only `CrossAgentOrigins` and `Provenance` survive the swap
// (:787-806): the loser's `CheckID`, `References` and `VerificationHints` are
// dropped on the floor, which is precisely the evidence a deterministic
// detector contributes and a model does not.
//
// Today that mattered rarely, because an LLM row and a skill row seldom landed
// on the same `(category, file, line)`. 0076's re-anchoring (P4,
// `VULTURE_LLM_QUOTE_REANCHOR`) rewrites `line_start` onto the line the quoted
// evidence actually occupies, which is exactly the line the skill row already
// reported — so it MANUFACTURES these collisions. That is why §5.5 calls this
// guard a hard prerequisite of re-anchoring rather than a follow-up, and why
// T4.1 lands before T4.2.
//
// THE CONTRACT PINNED HERE (AC15)
//
//  1. A deterministic row (any `Provenance` other than `llm`) NEVER loses a
//     cross-agent merge to an `llm` row at EQUAL OR LOWER severity — whatever
//     the detail score says, and regardless of the order the two rows arrive
//     in.
//  2. At STRICTLY HIGHER `llm` severity nothing changes. The guard is about
//     equal-or-lower only; it must not become a blanket "deterministic always
//     wins" rule, and it must not touch det-vs-det or llm-vs-llm merges.
//  3. `VULTURE_DEDUP_PREFER_DETERMINISTIC=false` restores the pre-0076 (0075)
//     winner selection EXACTLY — the richer row wins, `llm` included.
//     Unset/empty leaves the guard ON: it ships on, because it can only ever
//     preserve a deterministic finding, never delete one.
//  4. The survivor keeps its own `CheckID`, `References` and
//     `VerificationHints`, and still records the corroborating agent.
//
// The finding COUNT is invariant in every case below: this guard changes WHICH
// row survives a collapse that already happens, never HOW MANY rows survive.
//
// Note for the implementer: the switch is read at merge time (a plain
// `os.Getenv` in the merge path, as at :1352 and :1432). It must not be cached
// in a package-level `var`/`sync.Once`, or it stops being flippable — and
// these table cases, which set it per subtest, stop being meaningful.

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

const preferDeterministicEnv = "VULTURE_DEDUP_PREFER_DETERMINISTIC"

// provenanceRow builds a finding at ONE fixed collision site. Titles differ
// per row on purpose: `crossAgentKey` keys on the CWE category when it is set,
// so a model paraphrase of a skill row's title still collapses onto it — that
// is the collision re-anchoring creates.
func provenanceRow(id, agentType, provenance string, sev model.Severity) model.Finding {
	return model.Finding{
		ID:         id,
		AgentType:  agentType,
		Provenance: provenance,
		Severity:   sev,
		Category:   "CWE-89",
		Title:      "SQL injection reported by " + id,
		FilePath:   "src/db.py",
		LineStart:  42,
		LineEnd:    42,
	}
}

// deterministicRow is a skill row carrying exactly the evidence fields the
// merge drops when it loses: CheckID, References, VerificationHints.
// findingDetailScore at `high`: 40 + 1 ref + 2 hints + 1 check_id = 44.
func deterministicRow(id string, sev model.Severity) model.Finding {
	f := provenanceRow(id, "cwe", "skill", sev)
	f.CheckID = "cwe.sql_injection.string_concat"
	f.References = []string{"https://cwe.mitre.org/data/definitions/89.html"}
	f.VerificationHints = []string{"grep for string-concatenated SQL near line 42"}
	return f
}

// llmRow is an LLM-tier row: a model-authored snippet (+3) and however many
// references the model chose to list (+1 each, unbounded). The reference count
// is the second route past severity dominance, which is why one case below
// uses it to beat a deterministic row from a LOWER severity band.
func llmRow(id string, sev model.Severity, refs int) model.Finding {
	f := provenanceRow(id, "asvs", "llm", sev)
	f.CodeSnippet = `cursor.execute("SELECT * FROM users WHERE id = " + uid)`
	f.References = modelReferences(refs)
	return f
}

// modelReferences returns n distinct reference URLs. O(n).
func modelReferences(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "https://example.invalid/model-ref/"+string(rune('a'+i%26)))
	}
	return out
}

// richDeterministicRow is a second deterministic row (the semgrep plugin),
// richer than deterministicRow at the same severity: 40 + 5 refs + 3 snippet.
func richDeterministicRow(id string, sev model.Severity) model.Finding {
	f := provenanceRow(id, "semgrep", "semgrep", sev)
	f.CodeSnippet = `cursor.execute("SELECT * FROM users WHERE id = " + uid)`
	f.References = modelReferences(5)
	return f
}

type provenanceMergeCase struct {
	name string
	// prefer is the value of VULTURE_DEDUP_PREFER_DETERMINISTIC for this
	// case. "" means empty/unset — the shipped default, guard ON.
	prefer   string
	rows     [2]model.Finding
	wantID   string
	property string
}

// runProvenanceMergeCase feeds the pair through the merge in BOTH input
// orders. Winner selection is a property of the two rows, not of which agent's
// SSE frame arrived first, so a guard that only fires when the deterministic
// row happens to be seen first is not a guard.
func runProvenanceMergeCase(t *testing.T, c provenanceMergeCase) {
	t.Helper()
	t.Setenv(preferDeterministicEnv, c.prefer)
	orders := [][]model.Finding{
		{c.rows[0], c.rows[1]},
		{c.rows[1], c.rows[0]},
	}
	for _, in := range orders {
		out := deduplicateCrossAgent([]model.Finding{in[0], in[1]})
		if len(out) != 1 {
			t.Fatalf("same category+file+line must collapse to ONE finding "+
				"(the guard changes which row survives, never how many); got %d, order %q,%q",
				len(out), in[0].ID, in[1].ID)
		}
		if out[0].ID != c.wantID {
			t.Errorf("%s\n  %s=%q, input order %q,%q: survivor = %q (severity=%q provenance=%q), want %q",
				c.property, preferDeterministicEnv, c.prefer,
				in[0].ID, in[1].ID, out[0].ID, out[0].Severity, out[0].Provenance, c.wantID)
		}
	}
}

func TestDeduplicateCrossAgent_ProvenanceGuard(t *testing.T) {
	cases := []provenanceMergeCase{
		{
			// RED before T4.2: llm scores 40+3 refs+3 snippet = 46 against
			// the deterministic 44, so today the model row wins and the
			// check_id/references/hints are dropped.
			name:   "equal_severity_llm_richer_guard_default_on",
			prefer: "",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				llmRow("llm-row", model.SeverityHigh, 3),
			},
			wantID: "det-skill",
			property: "AC15: at EQUAL severity a deterministic row must never lose to an `llm` row, " +
				"however rich the model's row looks to findingDetailScore",
		},
		{
			// Same as above with the switch stated explicitly, so a build
			// that only honours an explicit "true" is still covered.
			name:   "equal_severity_llm_richer_guard_explicitly_true",
			prefer: "true",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				llmRow("llm-row", model.SeverityHigh, 3),
			},
			wantID: "det-skill",
			property: "AC15: VULTURE_DEDUP_PREFER_DETERMINISTIC=true must select the deterministic row " +
				"at equal severity",
		},
		{
			// RED before T4.2 via the SECOND route past the guard: severity
			// is lower (medium=30) but 12 model-authored references plus a
			// snippet total 45, beating the deterministic 44.
			name:   "lower_severity_llm_outscores_on_reference_count",
			prefer: "",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				llmRow("llm-row", model.SeverityMedium, 12),
			},
			wantID: "det-skill",
			property: "AC15: at LOWER severity a deterministic row must never lose to an `llm` row — " +
				"an unbounded reference list is not evidence",
		},
		{
			// Not over-constrained: the guard covers equal-or-lower only.
			// llm critical (50+3) still beats deterministic high (44).
			name:   "higher_severity_llm_still_wins_guard_on",
			prefer: "",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				llmRow("llm-row", model.SeverityCritical, 0),
			},
			wantID: "llm-row",
			property: "AC15 boundary: at STRICTLY HIGHER llm severity the 0075 behaviour is unchanged — " +
				"the guard must not become a blanket `deterministic always wins`",
		},
		{
			// The rollback switch restores 0075 EXACTLY: same two rows as
			// the first case, opposite winner.
			name:   "switch_off_restores_pre_0076_at_equal_severity",
			prefer: "false",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				llmRow("llm-row", model.SeverityHigh, 3),
			},
			wantID: "llm-row",
			property: "AC15 rollback: VULTURE_DEDUP_PREFER_DETERMINISTIC=false must restore pre-0076 " +
				"winner selection — the richer row wins, `llm` included",
		},
		{
			// The rollback switch on the reference-count route too.
			name:   "switch_off_restores_pre_0076_at_lower_severity",
			prefer: "false",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				llmRow("llm-row", model.SeverityMedium, 12),
			},
			wantID: "llm-row",
			property: "AC15 rollback: with the guard off, findingDetailScore alone decides — " +
				"no residual provenance term may leak through",
		},
		{
			// Scope: the guard keys on `llm` vs deterministic. Between two
			// deterministic rows the richer one still wins.
			name:   "two_deterministic_rows_richer_still_wins",
			prefer: "",
			rows: [2]model.Finding{
				deterministicRow("det-skill", model.SeverityHigh),
				richDeterministicRow("det-semgrep", model.SeverityHigh),
			},
			wantID: "det-semgrep",
			property: "the guard must not disturb det-vs-det merges (feature 0058 R6): " +
				"the richer deterministic row is still the keeper",
		},
		{
			// Scope: two `llm` rows are ranked by detail as before.
			name:   "two_llm_rows_richer_still_wins",
			prefer: "",
			rows: [2]model.Finding{
				llmRow("llm-bare", model.SeverityHigh, 0),
				llmRow("llm-rich", model.SeverityHigh, 6),
			},
			wantID: "llm-rich",
			property: "the guard must not disturb llm-vs-llm merges: with no deterministic row " +
				"present, findingDetailScore still decides",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runProvenanceMergeCase(t, c)
		})
	}
}

// The point of preserving the deterministic row is the evidence it carries.
// A guard that selects the right row but lets the merge overwrite its
// CheckID / References / VerificationHints delivers nothing, so the fields are
// asserted directly rather than inferred from the survivor's ID.
func TestDeduplicateCrossAgent_GuardKeepsDeterministicEvidenceFields(t *testing.T) {
	t.Setenv(preferDeterministicEnv, "")
	det := deterministicRow("det-skill", model.SeverityHigh)
	llm := llmRow("llm-row", model.SeverityHigh, 3)

	// llm first: the losing row is also the first-seen row.
	out := deduplicateCrossAgent([]model.Finding{llm, det})
	if len(out) != 1 {
		t.Fatalf("the colliding pair must collapse to ONE finding, got %d", len(out))
	}
	got := out[0]

	if got.CheckID != det.CheckID {
		t.Errorf("survivor CheckID = %q, want %q: the deterministic row's check id is the "+
			"stable identifier the frontend, dedup and L5 cache key all read", got.CheckID, det.CheckID)
	}
	if len(got.References) != len(det.References) || got.References[0] != det.References[0] {
		t.Errorf("survivor References = %v, want %v: the merge must not swap curated references "+
			"for model-authored ones", got.References, det.References)
	}
	if len(got.VerificationHints) != len(det.VerificationHints) ||
		got.VerificationHints[0] != det.VerificationHints[0] {
		t.Errorf("survivor VerificationHints = %v, want %v: the hints are how a reviewer "+
			"reproduces the finding; losing them makes the row unverifiable",
			got.VerificationHints, det.VerificationHints)
	}
	if got.Provenance == "llm" {
		t.Errorf("survivor Provenance = %q: a deterministic survivor must not be relabelled as "+
			"model-authored by the merge", got.Provenance)
	}
	if len(got.CrossAgentOrigins) != 1 || got.CrossAgentOrigins[0] != "asvs" {
		t.Errorf("survivor CrossAgentOrigins = %v, want [asvs]: corroboration by the other agent "+
			"must still be recorded on the row that survives", got.CrossAgentOrigins)
	}
}

// A deterministic row and an `llm` row at DIFFERENT sites are not a merge at
// all. Pinned so the guard cannot be implemented as a filter that drops `llm`
// rows: 0076 deletes no finding in any configuration (§5.7).
func TestDeduplicateCrossAgent_GuardNeverDropsANonCollidingLLMRow(t *testing.T) {
	t.Setenv(preferDeterministicEnv, "")
	det := deterministicRow("det-skill", model.SeverityHigh)
	llm := llmRow("llm-row", model.SeverityCritical, 2)
	llm.FilePath = "src/other.py"
	llm.LineStart = 7
	llm.LineEnd = 7

	out := deduplicateCrossAgent([]model.Finding{det, llm})

	if len(out) != 2 {
		t.Fatalf("distinct sites must both survive — the guard selects a merge winner, "+
			"it never deletes a finding; got %d findings", len(out))
	}
}

// TestIsLLMProvenance_CoversTheWholeFamily pins that the provenance classifier
// recognises every tag the agents actually emit, not just the bare "llm".
//
// Added during the 0076 simplify pass. `llm_l5_verified` is a real provenance
// (agents/shared/shared/validate/__init__.py:191 promotes a surviving LLM row to
// it, and 181 of 710 stored LLM rows on the measured target carry it). Matching
// only "llm" classified those rows as DETERMINISTIC, so the §5.5 guard silently
// did not apply to the LLM findings that went furthest through validation --
// exactly the rows most likely to claim a high severity.
func TestIsLLMProvenance_CoversTheWholeFamily(t *testing.T) {
	for _, tc := range []struct {
		provenance string
		want       bool
	}{
		{"llm", true},
		{"llm_l5_verified", true},
		{"LLM_L5_Verified", true},
		{" llm ", true},
		{"skill", false},
		{"catalog_rollup", false},
		{"signature_trusted", false},
		{"", false},
	} {
		if got := isLLMProvenance(model.Finding{Provenance: tc.provenance}); got != tc.want {
			t.Errorf("isLLMProvenance(%q) = %v, want %v", tc.provenance, got, tc.want)
		}
	}
}
