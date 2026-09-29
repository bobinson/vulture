//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// Feature 0096 §7.7 — the cache probe must not serve the pre-0096 OWASP shape.
//
// Before 0096 an OWASP run re-emitted every CWE finding as a second row with
// agent_type = owasp. From 0096 on, OWASP persists no rows of its own: it
// labels the CWE-categorised findings instead. A cache hit short-circuits the
// scan, so without this rule a request that includes `owasp` would be handed a
// completed pre-0096 audit — copy rows, double counts and all — and the new
// shape would never be produced for that source.
//
// The probe treats such an audit as a MISS. It does not fall back to an older
// audit either: the newest completed audit is the only candidate, and an older
// one is by definition staler than the scan the miss triggers.
//
// Requests whose types do not include `owasp` are unaffected: an audit that
// never ran the mapper cannot hold its rows.

type cacheSeedFinding struct {
	id       string
	agent    string
	category string // "" = CWE-798
	labels   []model.ComplianceLabel
}

type cacheSeedAudit struct {
	id       string
	types    []string
	at       time.Time
	findings []cacheSeedFinding
}

// seedCacheSource writes one source and its completed audits through the real
// SQLite repository, before the server opens the file.
func seedCacheSource(t *testing.T, base *repository.SQLiteRepo, sourceID string, audits ...cacheSeedAudit) {
	t.Helper()
	if err := base.CreateSource(&model.Source{ID: sourceID, Type: model.SourceTypeLocal,
		Path: "/work/" + sourceID, CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}); err != nil {
		t.Fatalf("create source %s: %v", sourceID, err)
	}
	for _, a := range audits {
		if err := base.CreateAudit(&model.Audit{ID: a.id, SourceID: sourceID, Types: a.types,
			Status: model.AuditStatusCompleted, CreatedAt: a.at.UTC().Truncate(time.Second)}); err != nil {
			t.Fatalf("create audit %s: %v", a.id, err)
		}
		rows := make([]model.Finding, 0, len(a.findings))
		for _, f := range a.findings {
			category := f.category
			if category == "" {
				category = "CWE-798"
			}
			rows = append(rows, model.Finding{ID: f.id, AuditID: a.id, AgentType: f.agent,
				Severity: model.SeverityHigh, Category: category, Title: "Hardcoded credential " + f.id,
				Description: "d", FilePath: "src/app.go", LineStart: 3, LineEnd: 3,
				Recommendation: "r", Fingerprint: "fp-" + f.id, ComplianceLabels: f.labels})
		}
		if err := base.SaveFindings(a.id, rows); err != nil {
			t.Fatalf("save findings for %s: %v", a.id, err)
		}
	}
}

// probeCache calls GET /api/audits/cache and returns the served audit id, ""
// on a miss.
func probeCache(t *testing.T, addr, sourceID, types string) string {
	t.Helper()
	resp, err := httpGet(addr, "/api/audits/cache?source_id="+sourceID+"&types="+types)
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		t.Fatalf("GET /api/audits/cache?source_id=%s&types=%s: status %d, want 200", sourceID, types, resp.StatusCode)
	}
	var out struct {
		Cached bool `json:"cached"`
		Audit  *struct {
			ID string `json:"id"`
		} `json:"audit"`
	}
	readJSON(t, resp, &out)
	if !out.Cached {
		return ""
	}
	if out.Audit == nil || out.Audit.ID == "" {
		t.Fatalf("cache hit for %s/%s carries no audit", sourceID, types)
	}
	return out.Audit.ID
}

func TestCacheSkipsLegacyOwaspShape(t *testing.T) {
	cfg := testConfig(t)
	base, err := repository.NewSQLiteRepo(cfg.DBPath)
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}

	now := time.Now().UTC()
	label := []model.ComplianceLabel{{Framework: "owasp", Edition: "2025",
		CategoryID: "A07", CategoryName: "Authentication Failures", CWE: "CWE-798"}}
	legacy := func(id string, at time.Time) cacheSeedAudit {
		return cacheSeedAudit{id: id, types: []string{"cwe", "owasp"}, at: at, findings: []cacheSeedFinding{
			{id: id + "-cwe", agent: "cwe"},
			{id: id + "-owasp-copy", agent: "owasp"},
		}}
	}
	labelled := func(id string, at time.Time) cacheSeedAudit {
		return cacheSeedAudit{id: id, types: []string{"cwe", "owasp"}, at: at, findings: []cacheSeedFinding{
			{id: id + "-cwe", agent: "cwe", labels: label},
		}}
	}

	// src-legacy-only: the only completed cwe+owasp audit is pre-0096.
	// Its cwe-only audit is a separate cache entry the rule must not touch.
	seedCacheSource(t, base, "src-legacy-only",
		legacy("audit-legacy-only", now.Add(-3*time.Hour)),
		cacheSeedAudit{id: "audit-cwe-only", types: []string{"cwe"}, at: now.Add(-2 * time.Hour),
			findings: []cacheSeedFinding{{id: "audit-cwe-only-f", agent: "cwe"}}},
	)
	// src-upgraded: a pre-0096 audit, then a post-0096 one.
	seedCacheSource(t, base, "src-upgraded",
		legacy("audit-upgraded-old", now.Add(-5*time.Hour)),
		labelled("audit-upgraded-new", now.Add(-1*time.Hour)),
	)
	// src-clean: a post-0096 audit of a clean tree (no rows at
	// all) is still the new shape.
	seedCacheSource(t, base, "src-clean",
		cacheSeedAudit{id: "audit-clean", types: []string{"cwe", "owasp"}, at: now.Add(-1 * time.Hour)},
	)
	// src-regressed: the newest audit carries OWASP rows (a pre-0096 agent
	// under version skew). It is a miss; the older post-0096 audit is not
	// served in its place.
	seedCacheSource(t, base, "src-regressed",
		labelled("audit-regressed-old", now.Add(-4*time.Hour)),
		legacy("audit-regressed-new", now.Add(-1*time.Hour)),
	)
	// src-owasp-only: a pre-0096 OWASP-only audit.
	seedCacheSource(t, base, "src-owasp-only",
		cacheSeedAudit{id: "audit-owasp-only", types: []string{"owasp"}, at: now.Add(-1 * time.Hour),
			findings: []cacheSeedFinding{{id: "audit-owasp-only-copy", agent: "owasp"}}},
	)
	// src-partly-labelled: a post-0096 audit where only some scanner rows
	// carry a label. A CWE no OWASP category maps (CWE-1004 here) gets none,
	// so an unlabelled scanner row is the ordinary new shape, not a sign of
	// the old one; treating it as a miss would make almost every real audit
	// uncacheable.
	seedCacheSource(t, base, "src-partly-labelled",
		cacheSeedAudit{id: "audit-partly-labelled", types: []string{"cwe", "xss", "owasp"},
			at: now.Add(-1 * time.Hour), findings: []cacheSeedFinding{
				{id: "partly-labelled-cwe", agent: "cwe", labels: label},
				{id: "partly-unlabelled-cwe", agent: "cwe", category: "CWE-1004"},
				{id: "partly-unlabelled-xss", agent: "xss", category: "CWE-1004"},
			}},
	)
	// src-no-labels: a post-0096 audit whose findings carry no label at all —
	// every CWE mapped to no category, or the mapping was rejected and the
	// run fell back to "no labels". It holds no OWASP rows, so it is the new
	// shape; the absence of labels is not evidence of the old one.
	seedCacheSource(t, base, "src-no-labels",
		cacheSeedAudit{id: "audit-no-labels", types: []string{"cwe", "owasp"},
			at: now.Add(-1 * time.Hour), findings: []cacheSeedFinding{
				{id: "no-labels-cwe", agent: "cwe", category: "CWE-1004"},
			}},
	)
	if err := base.Close(); err != nil {
		t.Fatalf("close seeding handle: %v", err)
	}

	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	for _, tc := range []struct {
		name, source, types, want string
	}{
		{"pre-0096 owasp audit is a miss", "src-legacy-only", "cwe,owasp", ""},
		{"type order does not matter", "src-legacy-only", "owasp,cwe", ""},
		{"types without owasp are unaffected", "src-legacy-only", "cwe", "audit-cwe-only"},
		{"post-0096 audit is served", "src-upgraded", "cwe,owasp", "audit-upgraded-new"},
		{"post-0096 audit with no rows is served", "src-clean", "cwe,owasp", "audit-clean"},
		{"newest audit holds owasp rows: miss, no fallback", "src-regressed", "cwe,owasp", ""},
		{"pre-0096 owasp-only audit is a miss", "src-owasp-only", "owasp", ""},
		{"post-0096 audit with unlabelled scanner rows is served", "src-partly-labelled", "cwe,owasp,xss",
			"audit-partly-labelled"},
		{"post-0096 audit with no labelled rows is served", "src-no-labels", "cwe,owasp", "audit-no-labels"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeCache(t, addr, tc.source, tc.types); got != tc.want {
				if tc.want == "" {
					t.Fatalf("cache served %q for %s types=%s; a completed audit holding agent_type=owasp "+
						"rows is the pre-0096 shape and must be a miss for a request including owasp",
						got, tc.source, tc.types)
				}
				t.Fatalf("cache for %s types=%s = %q, want %q", tc.source, tc.types, got, tc.want)
			}
		})
	}
}
