//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 — the audit comparison must not read the pre-0096 OWASP copies
// as remediated findings.
//
// Before 0096 an OWASP run re-emitted every CWE finding as a second row with
// agent_type = owasp. From 0096 on OWASP persists no rows of its own; it labels
// the CWE findings instead. Comparing a pre-0096 audit with a post-0096 one
// therefore finds every copy "missing" from the newer audit, and a naive diff
// reports each of them as fixed, although nothing in the code changed and each
// copy's CWE twin is compared on its own.
//
// Rule: when the NEWER of the two audits is in mapping mode (its types include
// owasp and it holds no owasp rows), the older audit's owasp rows are copies,
// not findings. They are left out of the new / fixed / persistent / changed
// classification and reported as `excluded_legacy_copies`. Every other pairing
// — both pre-0096, both post-0096, audits without owasp, or a newer audit that
// holds owasp rows again (a pre-0096 agent under version skew) — is compared
// exactly as before.

type compareSeedFinding struct {
	fp     string
	agent  string
	labels []model.ComplianceLabel
}

type compareSeedAudit struct {
	id       string
	types    []string
	at       time.Time
	findings []compareSeedFinding
}

// seedCompareSource writes one source and its completed audits through the
// real SQLite repository. Fingerprints are given explicitly so the same
// finding can appear in both audits of a pair.
func seedCompareSource(t *testing.T, base *repository.SQLiteRepo, sourceID string, audits ...compareSeedAudit) {
	t.Helper()
	if err := base.CreateSource(&model.Source{ID: sourceID, Type: model.SourceTypeLocal,
		Path: "/work/" + sourceID, CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}); err != nil {
		t.Fatalf("create source %s: %v", sourceID, err)
	}
	for _, a := range audits {
		at := a.at.UTC().Truncate(time.Second)
		if err := base.CreateAudit(&model.Audit{ID: a.id, SourceID: sourceID, Types: a.types,
			Status: model.AuditStatusCompleted, CreatedAt: at, CompletedAt: &at}); err != nil {
			t.Fatalf("create audit %s: %v", a.id, err)
		}
		rows := make([]model.Finding, 0, len(a.findings))
		for _, f := range a.findings {
			rows = append(rows, model.Finding{ID: a.id + "-" + f.fp, AuditID: a.id, AgentType: f.agent,
				Severity: model.SeverityHigh, Category: "CWE-798", Title: "Hardcoded credential " + f.fp,
				Description: "d", FilePath: "src/app.go", LineStart: 3, LineEnd: 3,
				Recommendation: "r", Fingerprint: f.fp, ComplianceLabels: f.labels})
		}
		if err := base.SaveFindings(a.id, rows); err != nil {
			t.Fatalf("save findings for %s: %v", a.id, err)
		}
	}
}

type compareSummary struct {
	Fingerprint string `json:"fingerprint"`
	AgentType   string `json:"agent_type"`
}

type compareResponse struct {
	HasPrevious          bool             `json:"has_previous"`
	PreviousAuditID      string           `json:"previous_audit_id"`
	NewCount             int              `json:"new_count"`
	FixedCount           int              `json:"fixed_count"`
	PersistentCount      int              `json:"persistent_count"`
	ChangedCount         int              `json:"changed_count"`
	ExcludedLegacyCopies int              `json:"excluded_legacy_copies"`
	NewFindings          []compareSummary `json:"new_findings"`
	FixedFindings        []compareSummary `json:"fixed_findings"`
}

func getComparison(t *testing.T, addr, auditID string) compareResponse {
	t.Helper()
	resp, err := httpGet(addr, "/api/audits/"+auditID+"/comparison")
	if err != nil {
		t.Fatalf("GET comparison for %s: %v", auditID, err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		t.Fatalf("GET /api/audits/%s/comparison: status %d, want 200", auditID, resp.StatusCode)
	}
	var out compareResponse
	readJSON(t, resp, &out)
	if !out.HasPrevious {
		t.Fatalf("comparison for %s has no previous audit", auditID)
	}
	return out
}

func fingerprintsOf(rows []compareSummary) map[string]string {
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r.Fingerprint] = r.AgentType
	}
	return m
}

type compareWant struct {
	previous                         string
	newCount, fixedCount, persistent int
	excluded                         int
	newFPs, fixedFPs                 []string
}

func assertComparison(t *testing.T, got compareResponse, want compareWant) {
	t.Helper()
	if got.PreviousAuditID != want.previous {
		t.Fatalf("previous_audit_id = %q, want %q", got.PreviousAuditID, want.previous)
	}
	if got.FixedCount != want.fixedCount || len(got.FixedFindings) != len(want.fixedFPs) {
		t.Errorf("fixed_count = %d (%v), want %d %v; a pre-0096 OWASP copy is not a remediated finding",
			got.FixedCount, fingerprintsOf(got.FixedFindings), want.fixedCount, want.fixedFPs)
	}
	if got.NewCount != want.newCount || len(got.NewFindings) != len(want.newFPs) {
		t.Errorf("new_count = %d (%v), want %d %v", got.NewCount, fingerprintsOf(got.NewFindings),
			want.newCount, want.newFPs)
	}
	if got.PersistentCount != want.persistent {
		t.Errorf("persistent_count = %d, want %d", got.PersistentCount, want.persistent)
	}
	if got.ChangedCount != 0 {
		t.Errorf("changed_count = %d, want 0", got.ChangedCount)
	}
	if got.ExcludedLegacyCopies != want.excluded {
		t.Errorf("excluded_legacy_copies = %d, want %d", got.ExcludedLegacyCopies, want.excluded)
	}
	fixed, added := fingerprintsOf(got.FixedFindings), fingerprintsOf(got.NewFindings)
	for _, fp := range want.fixedFPs {
		if _, ok := fixed[fp]; !ok {
			t.Errorf("fixed_findings %v lacks %s", fixed, fp)
		}
	}
	for _, fp := range want.newFPs {
		if _, ok := added[fp]; !ok {
			t.Errorf("new_findings %v lacks %s", added, fp)
		}
	}
}

func TestCompareExcludesLegacyOwaspCopies(t *testing.T) {
	cfg := testConfig(t)
	base, err := repository.NewSQLiteRepo(cfg.DBPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}

	now := time.Now().UTC()
	label := []model.ComplianceLabel{{Framework: "owasp", Edition: "2025",
		CategoryID: "A07", CategoryName: "Authentication Failures", CWE: "CWE-798"}}
	cwe := func(fp string) compareSeedFinding { return compareSeedFinding{fp: fp, agent: "cwe"} }
	labelled := func(fp string) compareSeedFinding { return compareSeedFinding{fp: fp, agent: "cwe", labels: label} }
	copyOf := func(fp string) compareSeedFinding { return compareSeedFinding{fp: fp, agent: "owasp"} }
	both := []string{"cwe", "owasp"}

	// Upgrade: a pre-0096 audit (two CWE rows + their OWASP copies), then a
	// post-0096 audit where one CWE row is still present, labelled, and the
	// other was genuinely fixed.
	seedCompareSource(t, base, "src-cmp-upgrade",
		compareSeedAudit{id: "cmp-upgrade-old", types: both, at: now.Add(-3 * time.Hour), findings: []compareSeedFinding{
			cwe("fp-up-a"), cwe("fp-up-b"), copyOf("fp-up-copy-a"), copyOf("fp-up-copy-b"),
		}},
		compareSeedAudit{id: "cmp-upgrade-new", types: both, at: now.Add(-1 * time.Hour), findings: []compareSeedFinding{
			labelled("fp-up-a"),
		}},
	)
	// Reverse direction (version skew): a post-0096 audit, then a newer audit
	// written by a pre-0096 agent that holds OWASP rows again. The newer audit
	// is not in mapping mode, so its rows are compared as before.
	seedCompareSource(t, base, "src-cmp-skew",
		compareSeedAudit{id: "cmp-skew-old", types: both, at: now.Add(-3 * time.Hour), findings: []compareSeedFinding{
			labelled("fp-sk-a"),
		}},
		compareSeedAudit{id: "cmp-skew-new", types: both, at: now.Add(-1 * time.Hour), findings: []compareSeedFinding{
			cwe("fp-sk-a"), copyOf("fp-sk-copy-a"),
		}},
	)
	// Both pre-0096: OWASP rows on both sides are compared as before.
	seedCompareSource(t, base, "src-cmp-legacy",
		compareSeedAudit{id: "cmp-legacy-old", types: both, at: now.Add(-3 * time.Hour), findings: []compareSeedFinding{
			cwe("fp-lg-a"), cwe("fp-lg-b"), copyOf("fp-lg-copy-a"), copyOf("fp-lg-copy-b"),
		}},
		compareSeedAudit{id: "cmp-legacy-new", types: both, at: now.Add(-1 * time.Hour), findings: []compareSeedFinding{
			cwe("fp-lg-a"), copyOf("fp-lg-copy-a"),
		}},
	)
	// No owasp in the types: unaffected.
	seedCompareSource(t, base, "src-cmp-cwe",
		compareSeedAudit{id: "cmp-cwe-old", types: []string{"cwe"}, at: now.Add(-3 * time.Hour),
			findings: []compareSeedFinding{cwe("fp-cw-a"), cwe("fp-cw-b")}},
		compareSeedAudit{id: "cmp-cwe-new", types: []string{"cwe"}, at: now.Add(-1 * time.Hour),
			findings: []compareSeedFinding{cwe("fp-cw-a")}},
	)
	if err := base.Close(); err != nil {
		t.Fatalf("close seeding handle: %v", err)
	}

	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	t.Run("pre-0096 vs post-0096: copies are neither fixed nor persistent", func(t *testing.T) {
		assertComparison(t, getComparison(t, addr, "cmp-upgrade-new"), compareWant{
			previous: "cmp-upgrade-old", fixedCount: 1, persistent: 1, excluded: 2,
			fixedFPs: []string{"fp-up-b"},
		})
	})
	t.Run("comparing the older audit against the newer one: copies are not new", func(t *testing.T) {
		// The comparison of the older audit resolves the newer one as its
		// counterpart; the newer audit is still the one in mapping mode.
		got := getComparison(t, addr, "cmp-upgrade-old")
		for _, row := range got.NewFindings {
			if row.AgentType == "owasp" {
				t.Errorf("new_findings holds pre-0096 OWASP copy %s", row.Fingerprint)
			}
		}
		assertComparison(t, got, compareWant{
			previous: "cmp-upgrade-new", newCount: 1, persistent: 1, excluded: 2,
			newFPs: []string{"fp-up-b"},
		})
	})
	t.Run("newer audit holds owasp rows (skew): unchanged", func(t *testing.T) {
		assertComparison(t, getComparison(t, addr, "cmp-skew-new"), compareWant{
			previous: "cmp-skew-old", newCount: 1, persistent: 1,
			newFPs: []string{"fp-sk-copy-a"},
		})
	})
	t.Run("both pre-0096: unchanged", func(t *testing.T) {
		assertComparison(t, getComparison(t, addr, "cmp-legacy-new"), compareWant{
			previous: "cmp-legacy-old", fixedCount: 2, persistent: 2,
			fixedFPs: []string{"fp-lg-b", "fp-lg-copy-b"},
		})
	})
	t.Run("audits without owasp: unchanged", func(t *testing.T) {
		assertComparison(t, getComparison(t, addr, "cmp-cwe-new"), compareWant{
			previous: "cmp-cwe-old", fixedCount: 1, persistent: 1,
			fixedFPs: []string{"fp-cw-b"},
		})
	})
}
