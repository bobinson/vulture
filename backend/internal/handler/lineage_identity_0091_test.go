package handler

import (
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 §7.3 — THE MATCHING KEY HAS TO EXIST.
//
// THE DEFECT THESE PIN. §7.3 makes `fingerprint_v2` the identity a lineage row
// is matched by, precisely because v1 hashes the RAW file path and therefore
// changes when the mount does. Six separate places read it — `identityKeysOf`,
// `scanPass.reported`, `indexLineageByIdentity`, `resolveExisting`,
// `GetLineageByFingerprintsForTarget`, and migration 027's `uq_lineage_target`
// / duplicate-merge key. Exactly ONE place writes it: `stampIdentity`, which
// returned before computing anything unless an operator had set
// VULTURE_FINDING_IDENTITY — a variable that appears in no compose file, no
// .env and no deployment guide.
//
// So on every shipped configuration v2 was the empty string on every finding
// and every lineage row, every one of those six readers degenerated to v1, and
// the feature's central claim ("a native→docker switch produces the same key")
// was false in the only configuration anyone runs.
//
// WHY THE EXISTING S16 TEST COULD NOT CATCH IT. `detTargetFinding` /
// `llmTargetFinding` in test/e2e/lineage_target_test.go pass a LITERAL v2 on
// every finding. That is what the pipeline is supposed to produce, so the test
// measures the matching rule correctly and the production of the value not at
// all. These tests take the value from the code that really computes it.

// mountedFinding is one finding as a scan standing at `root` emits it: the
// file path in that scan's coordinates, and the v1 fingerprint the stream
// handler derives from that raw path.
func mountedFinding(root, rel string) model.Finding {
	f := model.Finding{
		AgentType:   "cwe",
		Severity:    model.SeverityHigh,
		Category:    "CWE-502",
		Title:       "Unsafe deserialisation of request body",
		CheckID:     "cwe.deserialisation.pickle",
		FilePath:    filepath.Join(root, rel),
		LineStart:   7,
		LineEnd:     7,
		Provenance:  "skill",
		Description: "seeded by the 0091 identity test",
	}
	f.Fingerprint = generateFingerprint(f.Title, f.FilePath, f.Category, f.AgentType)
	return f
}

// TestStampIdentityProducesTheMatchingKeyAtShippedDefaults is the wire itself.
//
// Two mounts of one tree, one finding. The contract §7.3 depends on is that
// the stamped identity is NON-EMPTY (or nothing matches on it) and EQUAL
// across the mounts (or matching on it is no better than v1).
func TestStampIdentityProducesTheMatchingKeyAtShippedDefaults(t *testing.T) {

	native := mountedFinding("/home/x/proj", "src/api.py")
	docker := mountedFinding("/mnt/source/proj", "src/api.py")
	if native.Fingerprint == docker.Fingerprint {
		t.Fatal("fixture is wrong: v1 hashes the raw path, so the two mounts must differ")
	}

	batchA := []model.Finding{native}
	batchB := []model.Finding{docker}
	stampIdentity(batchA, "/home/x/proj")
	stampIdentity(batchB, "/mnt/source/proj")

	if batchA[0].FingerprintV2 == "" {
		t.Fatal("no fingerprint_v2 was stamped at shipped defaults: §7.3 makes it the key " +
			"lineage matches on, and the empty string matches nothing — every reader of it " +
			"silently falls back to the raw-path v1 the feature exists to stop using")
	}
	if batchA[0].FingerprintV2 != batchB[0].FingerprintV2 {
		t.Fatalf("the same finding under two mounts must carry ONE identity: %q vs %q",
			batchA[0].FingerprintV2, batchB[0].FingerprintV2)
	}
	// observe semantics survive: v2 is written, but nothing is swapped. Only
	// VULTURE_FINDING_IDENTITY=enforce may move `fingerprint` itself, because
	// that rewrite is the half that cannot be undone.
	if batchA[0].Fingerprint != native.Fingerprint {
		t.Errorf("the default must not swap the resolution key: %q became %q",
			native.Fingerprint, batchA[0].Fingerprint)
	}
	if batchA[0].LegacyFingerprint != "" {
		t.Error("LegacyFingerprint belongs to the enforce swap; nothing is being bridged here")
	}
}

// TestMountChangeCarriesTheRowForwardThroughTheStampedIdentity is the
// consequence, over the real service and a real store, with every identity
// derived by production code rather than written into the fixture.
//
// Both directions of the damage are asserted, because the stored path decides
// which one you get:
//
//   - an ABSOLUTE stored path is unplaceable against the new root, so the
//     scope check saves it from closure — and it is duplicated instead: a
//     second row, a second VLT ref, a second first-seen date, and the
//     accepted_risk / notes / ticket on the first row orphaned.
//   - a RELATIVE stored path (roughly a quarter of the live table) IS
//     placeable, so nothing stops the deterministic rule, and the row is
//     closed as repaired by a scan that re-found it under another name.
func TestMountChangeCarriesTheRowForwardThroughTheStampedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		firstRel string // how scan 1 reports (and therefore stores) the path
	}{
		{name: "absolute_stored_path", firstRel: ""},
		{name: "relative_stored_path", firstRel: "src/api.py"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newIdentityStack(t)

			first := mountedFinding("/home/x/proj", "src/api.py")
			if tc.firstRel != "" {
				first.FilePath = tc.firstRel
				first.Fingerprint = generateFingerprint(
					first.Title, first.FilePath, first.Category, first.AgentType)
			}
			batch := []model.Finding{first}
			stampIdentity(batch, "/home/x/proj")
			if err := svc.RecordScanOutcome(
				identityAudit("audit-mount-1"), identitySource("src-1", "/home/x/proj"),
				"cwe", identityResult(batch...)); err != nil {
				t.Fatalf("scan 1: %v", err)
			}
			before := identityRows(t, repo, "/home/x/proj", "/mnt/source/proj")
			if len(before) != 1 {
				t.Fatalf("scan 1 must create exactly one lineage row, got %d", len(before))
			}
			var rowID string
			for id := range before {
				rowID = id
			}

			// Scan 2: the same tree through the compose bind mount. Nothing
			// about the code changed.
			second := []model.Finding{mountedFinding("/mnt/source/proj", "src/api.py")}
			stampIdentity(second, "/mnt/source/proj")
			if err := svc.RecordScanOutcome(
				identityAudit("audit-mount-2"), identitySource("src-2", "/mnt/source/proj"),
				"cwe", identityResult(second...)); err != nil {
				t.Fatalf("scan 2: %v", err)
			}

			after := identityRows(t, repo, "/home/x/proj", "/mnt/source/proj")
			if len(after) != 1 {
				t.Errorf("one finding under two mounts must stay ONE lineage row, got %d — "+
					"the mount change minted a duplicate and orphaned the first row's triage",
					len(after))
			}
			now, err := repo.GetLineage(rowID)
			if err != nil || now == nil {
				t.Fatalf("re-read lineage %s: %v", rowID, err)
			}
			if now.CurrentStatus != model.LineageStatusOpen {
				t.Errorf("a mount change is not a fact about the code, so the row must stay "+
					"%q — got %q", model.LineageStatusOpen, now.CurrentStatus)
			}
		})
	}
}

func newIdentityStack(t *testing.T) (service.LineageService, repository.LineageRepository) {
	t.Helper()
	base, err := repository.NewSQLiteRepo(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatalf("open sqlite repo: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	repo := repository.NewSQLiteLineageRepo(base.DB())
	return service.NewLineageService(repo), repo
}

func identitySource(id, path string) *model.Source {
	return &model.Source{
		ID: id, Type: model.SourceTypeGit, Path: path,
		URL:          "https://github.com/acme/proj.git",
		GitRemoteURL: "https://github.com/acme/proj.git",
		GitBranch:    "main", GitCommitShort: "abc1234",
	}
}

func identityAudit(id string) *model.Audit {
	return &model.Audit{ID: id, SourceID: "src-1", Types: []string{"cwe"}}
}

func identityResult(findings ...model.Finding) *model.ScanResult {
	return &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{},
		Findings:     findings,
	}
}

// identityRows collects the lineage rows visible from either mount, keyed by
// id, so a duplicate raises the count however the read resolves a path.
func identityRows(t *testing.T, repo repository.LineageRepository,
	paths ...string) map[string]model.FindingLineage {
	t.Helper()
	out := map[string]model.FindingLineage{}
	for _, p := range paths {
		rows, err := repo.ListBySourcePath(p, "", 500, 0)
		if err != nil {
			t.Fatalf("list lineage under %q: %v", p, err)
		}
		for _, r := range rows {
			out[r.ID] = r
		}
	}
	return out
}
