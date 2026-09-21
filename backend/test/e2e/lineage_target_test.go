//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/internal/service"
)

// Feature 0091 P3 — TARGET IDENTITY. What counts as "the same codebase".
//
// THE DEFECT THESE TESTS PIN. Lineage is partitioned by `source_path`, the
// absolute directory the scan happened to run in. That string is not a
// property of the codebase; it is a property of HOW the codebase was mounted:
//
//	/home/user/src/vulture          native run
//	/mnt/source/vulture             the same tree, docker
//	/tmp/vulture-sources/<sha+ts>/  a git ingest — a FRESH directory every run
//
// So the partition key changes when nothing about the code changed. Two things
// follow, and both are wrong. First, every finding is recorded again under the
// new path: a second lineage row, a second VLT ref, a second "first seen"
// date, and the human triage attached to the first row (accepted_risk, notes,
// ticket) is silently orphaned. Second — and this is the one that destroys
// data rather than merely duplicating it — once the partitions are UNIFIED so
// that history survives a mount change (LLD D3, §7), the old rows become
// visible to the new scan's closure pass. If they are not also MATCHED, the
// pass sees every one of them missing from the result and closes the lot.
// A path-form change would mass-close the entire corpus in one run.
//
// THE CONTRACT (LLD §7). Grouping is by `target_key` — a canonical identity
// derived from the git remote, else a scan-root marker, else the canonicalised
// path (§7.1) — and a sub-path scan inherits its root's key (§7.2). Rows are
// MATCHED inside that group by `fingerprint_v2`, the 0079 path-canonical
// identity, falling back to v1 for rows that predate it (§7.3). v1 embeds the
// absolute path and therefore changes with the mount; v2 does not, which is
// exactly why matching must use it. Closure stays per BRANCH (§7.4): a file
// that is absent because you are standing on another branch has not been
// fixed.
//
// Three guards, each for one way the naive fix goes wrong:
//
//	S16  TestRunModeSwitchDoesNotMassFix        — a mount change is not a repair
//	S14  TestSubPathScanNeverClosesOutsideScope — unified partitions need scope
//	S24  TestBranchSwitchDoesNotClose           — one target, many branches
//
// Every test below carries a DETERMINISTIC row, because the deterministic tier
// is the one that closes on absence: it is the tier a target-identity mistake
// actually destroys. Where an LLM row is present too it is a second, different
// discriminator — a mismatched LLM row does not close, it goes `unconfirmed`,
// which is a status transition all the same and just as much a lie about what
// the scan observed.

// targetRemote is one repository, seen through every mount below. In §7.1
// terms it resolves via step 1: a git remote exists, so the target key is
// `git:<normalised remote>` and the host path is irrelevant to identity.
const targetRemote = "https://github.com/acme/proj.git"

// targetQuoteHash stands in for the sha256 the agent stamps on an LLM finding
// when it first emits it. Its value is opaque to the backend; what matters is
// that an LLM-tier row carries one, because that is what makes it checkable.
const targetQuoteHash = "sha256:11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"

// targetSource builds the source record for one scan of one mount of the
// shared repository. GitRemoteURL is what makes the two mounts the same
// target; Path is what makes them look different today.
func targetSource(id, path, branch string) *model.Source {
	return &model.Source{
		ID:             id,
		Type:           model.SourceTypeGit,
		URL:            targetRemote,
		Path:           path,
		GitRemoteURL:   targetRemote,
		GitBranch:      branch,
		GitCommitShort: "abc1234",
	}
}

// targetLocalSource is the non-git case: identity comes from a scan-root
// marker on disk (§7.1 step 2), and there is no branch, so per-branch closure
// never engages and the scope check is the only thing standing between a
// sub-path scan and the rows outside it.
func targetLocalSource(id, path string) *model.Source {
	return &model.Source{ID: id, Type: model.SourceTypeLocal, Path: path}
}

// detTargetFinding is a deterministic (skill-tier) finding. v1 and v2 are
// passed separately and deliberately: v1 is what a real scan derives from the
// absolute path and therefore CHANGES between mounts, v2 is the 0079
// path-canonical identity and does not. Every test here turns on that
// difference.
func detTargetFinding(v1, v2, filePath string) model.Finding {
	return model.Finding{
		AgentType:     "cwe",
		Severity:      model.SeverityHigh,
		Category:      "CWE-78",
		Title:         "Command injection in build task",
		FilePath:      filePath,
		LineStart:     7,
		LineEnd:       7,
		Fingerprint:   v1,
		FingerprintV2: v2,
		Provenance:    "skill",
	}
}

// llmTargetFinding is the same shape in the LLM tier: provenance in the `llm*`
// family, plus the quote hash that makes evidence verification possible.
func llmTargetFinding(v1, v2, filePath string) model.Finding {
	f := detTargetFinding(v1, v2, filePath)
	f.Title = "Unsafe deserialisation of request body"
	f.Category = "CWE-502"
	f.Provenance = "llm_l5_verified"
	f.QuoteHash = targetQuoteHash
	return f
}

// targetNoise keeps the agent present in the result without touching any
// tracked row: a result carrying nothing at all for an agent closes nothing,
// so every "the finding was not reported" scan below still has to report
// something.
func targetNoise(v1 string) model.Finding {
	f := detTargetFinding(v1, v1+"-v2", "src/noise.py")
	f.Title = "Unrelated noise"
	return f
}

// evidenceResult is a result event from an agent that speaks 0091: it declares
// its schema and reports what the walker pruned, so scope is KNOWN and the
// closure pass is allowed to act. Without this an old-agent result (S26)
// disables LLM-tier closure entirely and the tests below would pass for the
// wrong reason.
func evidenceResult(findings ...model.Finding) *model.ScanResult {
	return &model.ScanResult{
		ResultSchema: model.ScanResultSchemaEvidence,
		PrunedDirs:   []string{},
		Findings:     findings,
	}
}

// lineageRowsAcross collects the lineage rows visible from any of the given
// path forms, keyed by row id.
//
// Keyed by id, and taken over EVERY path form, so the assertion "one finding
// is one row" holds however the implementation chooses to resolve a path to a
// target: if `ListBySourcePath` resolves through the target key the same rows
// come back from both paths and dedupe here; if it stays literal, each path
// contributes its own. Either way a DUPLICATE — the same finding recorded
// twice because the mount changed — raises the count, which is the defect
// being measured.
func lineageRowsAcross(t *testing.T, repo repository.LineageRepository, paths ...string) map[string]model.FindingLineage {
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

// summarizeRows renders a row set as one short line per row. A failure here is
// about WHICH rows exist, never about their column values, and dumping whole
// structs buries that in several kilobytes of timestamps.
func summarizeRows(rows map[string]model.FindingLineage) string {
	out := ""
	for _, r := range rows {
		out += fmt.Sprintf("\n    %s  v2=%-14s ref=%-3d status=%-8s under %s",
			r.ID[:8], r.FingerprintV2, r.RefNumber, r.CurrentStatus, r.SourcePath)
	}
	return out
}

// reloadLineage re-reads one row by id. By ID, never by (fingerprint, path):
// the whole question under test is which row a given path resolves to, so a
// path-keyed re-read could not tell a carried-forward row from a fresh
// duplicate.
func reloadLineage(t *testing.T, repo repository.LineageRepository, id string) *model.FindingLineage {
	t.Helper()
	l, err := repo.GetLineage(id)
	if err != nil {
		t.Fatalf("get lineage %q: %v", id, err)
	}
	if l == nil {
		t.Fatalf("lineage row %q disappeared", id)
	}
	return l
}

// transitionEvents returns the events on a row that assert a CHANGE of state,
// as opposed to the informational ones (out_of_scope, scope_unknown,
// confirmed_by_evidence, skipped_degraded) that record what a scan observed.
//
// "Zero transitions" is the measurable form of "a mount change is not a fact
// about the code", so it gets its own helper rather than a per-test list.
func transitionEvents(t *testing.T, repo repository.LineageRepository, lineageID string) []model.LineageEventType {
	t.Helper()
	transitional := map[model.LineageEventType]bool{
		model.LineageEventFixed:         true,
		model.LineageEventEvidenceGone:  true,
		model.LineageEventRegression:    true,
		model.LineageEventUnconfirmable: true,
		model.LineageEventStatusChange:  true,
	}
	out := []model.LineageEventType{}
	for _, e := range eventTypesOf(t, repo, lineageID) {
		if transitional[e] {
			out = append(out, e)
		}
	}
	return out
}

// TestRunModeSwitchDoesNotMassFix is scenario S16 — THE ACCEPTANCE TEST FOR
// TARGET IDENTITY, and the one that stops a path-form change from mass-closing
// every finding in a codebase.
//
// The same tree is scanned twice with nothing changed but the mount. The
// second scan re-reports both findings; because v1 embeds the absolute path,
// it reports them under DIFFERENT v1 fingerprints and the SAME
// `fingerprint_v2`. That is not a contrivance — it is what the two tiers
// actually emit, and it is the reason §7.3 makes v2 the matching key.
//
// The contract has two halves and both are load-bearing:
//
//   - ZERO status transitions. Not one row closed, regressed, or made
//     unconfirmed. A directory rename is not evidence of repair, and after the
//     partitions are unified the old rows are visible to the new scan's
//     closure pass — so "the old partition is simply invisible" stops being
//     what protects them.
//   - ZERO duplicates. One finding is one lineage row, keeping its id, its VLT
//     ref and its first-seen date, because a duplicate row silently orphans
//     the accepted_risk / false_positive / notes / ticket a human attached to
//     the first one.
func TestRunModeSwitchDoesNotMassFix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first string
		then  string
	}{
		{
			// The documented run-mode switch: a host checkout, then the same
			// checkout bind-mounted into the agent container.
			name:  "native_to_docker_mount",
			first: "/home/x/proj",
			then:  "/mnt/source/proj",
		},
		{
			// Git ingest writes to /tmp/vulture-sources/<sha+now>/run-<id>/, a
			// fresh directory on EVERY ingest. Under a path partition this
			// target can never accumulate history at all: every scan is the
			// first scan, and every previous scan's rows are stranded.
			name:  "fresh_clone_directory_each_ingest",
			first: "/tmp/vulture-sources/a1b2c3-1700000000/run-1",
			then:  "/tmp/vulture-sources/d4e5f6-1700009999/run-2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newLineageStack(t)

			// Scan 1, first mount. One row per tier.
			first := targetSource("src-first", tc.first, "main")
			seed := evidenceResult(
				detTargetFinding("fp-v1-det-first", "fpv2-det", "src/build.py"),
				llmTargetFinding("fp-v1-llm-first", "fpv2-llm", "src/api.py"),
			)
			if err := svc.RecordScanOutcome(lineageTestAudit("audit-target-1"), first, "cwe", seed); err != nil {
				t.Fatalf("scan 1: %v", err)
			}

			before := lineageRowsAcross(t, repo, tc.first)
			if len(before) != 2 {
				t.Fatalf("scan 1 must create exactly one lineage row per finding, got %d: %v",
					len(before), summarizeRows(before))
			}
			byV2 := map[string]model.FindingLineage{}
			for _, r := range before {
				byV2[r.FingerprintV2] = r
			}
			detBefore, ok := byV2["fpv2-det"]
			if !ok {
				t.Fatalf("no lineage row carrying fingerprint_v2 %q after scan 1:%s", "fpv2-det", summarizeRows(before))
			}
			llmBefore, ok := byV2["fpv2-llm"]
			if !ok {
				t.Fatalf("no lineage row carrying fingerprint_v2 %q after scan 1:%s", "fpv2-llm", summarizeRows(before))
			}

			// Scan 2, second mount, identical code. Same findings, same v2,
			// new v1 — because v1 is derived from the absolute path.
			second := targetSource("src-second", tc.then, "main")
			rescan := evidenceResult(
				detTargetFinding("fp-v1-det-second", "fpv2-det", "src/build.py"),
				llmTargetFinding("fp-v1-llm-second", "fpv2-llm", "src/api.py"),
			)
			if err := svc.RecordScanOutcome(lineageTestAudit("audit-target-2"), second, "cwe", rescan); err != nil {
				t.Fatalf("scan 2: %v", err)
			}

			// ── Half one: no duplicates. ───────────────────────────────────
			after := lineageRowsAcross(t, repo, tc.first, tc.then)
			if len(after) != 2 {
				t.Fatalf("the same two findings under a different mount must remain TWO lineage "+
					"rows, not %d: a path-form change created a duplicate lineage, and the triage "+
					"attached to the original row is now orphaned. Rows:%s", len(after), summarizeRows(after))
			}

			// ── Half two: no transitions. ──────────────────────────────────
			for _, row := range []model.FindingLineage{detBefore, llmBefore} {
				now := reloadLineage(t, repo, row.ID)
				if now.CurrentStatus != model.LineageStatusOpen {
					t.Fatalf("%s row (fingerprint_v2 %q): a mount change is not a fact about the "+
						"code, so the row must stay %q — got %q",
						model.TierOf(row.Provenance), row.FingerprintV2,
						model.LineageStatusOpen, now.CurrentStatus)
				}
				if trans := transitionEvents(t, repo, row.ID); len(trans) != 0 {
					t.Fatalf("%s row (fingerprint_v2 %q): expected ZERO status transitions across a "+
						"run-mode switch, got %v",
						model.TierOf(row.Provenance), row.FingerprintV2, trans)
				}
				if now.RefNumber != row.RefNumber {
					t.Fatalf("%s row (fingerprint_v2 %q): the VLT ref must survive a mount change: "+
						"%d -> %d", model.TierOf(row.Provenance), row.FingerprintV2,
						row.RefNumber, now.RefNumber)
				}
				if !now.FirstFoundAt.Equal(row.FirstFoundAt) {
					t.Fatalf("%s row (fingerprint_v2 %q): first_found_at must survive a mount "+
						"change: %s -> %s", model.TierOf(row.Provenance), row.FingerprintV2,
						row.FirstFoundAt, now.FirstFoundAt)
				}
				if now.SeenCount != 2 {
					t.Fatalf("%s row (fingerprint_v2 %q): the second scan DID report this finding, "+
						"so it was seen twice: seen_count = %d, want 2",
						model.TierOf(row.Provenance), row.FingerprintV2, now.SeenCount)
				}
			}
		})
	}
}

// targetTreeWithMarker builds a real scan root whose identity comes from a
// scan-root marker (§7.1 step 2, the blu-simulator case): a directory holding
// `package.json`, with the two subtrees the sub-path test needs.
//
// Real directories, not fabricated strings, because a sub-path scan's identity
// is the identity of an ANCESTOR — the resolver has to be able to climb, and
// the offset it computes ("sub") is what the scope check is built from.
func targetTreeWithMarker(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	write("package.json", `{"name":"proj","version":"1.0.0"}`)
	write("sub/a.py", "import os\nos.system(cmd)\n")
	write("other/b.py", "import pickle\npickle.loads(blob)\n")
	return root
}

// TestSubPathScanNeverClosesOutsideScope is scenario S14, and it is the guard
// that makes unifying the partitions safe at all.
//
// Today a scan of `<root>/sub` cannot damage a finding in `<root>/other` for
// an accidental reason: they live in different `source_path` partitions, so
// the closure pass never even loads the root's rows. Once `<root>/sub`
// inherits the root's target key (§7.2) — which it must, or a sub-path scan
// starts a second history for the same codebase — that accident is gone and
// the rows ARE loaded. The only thing left between them and closure is scope
// (§6.5): a scan may close a row only where it actually looked.
//
// So the contract is three statements at once:
//
//   - the row under `other/` is UNTOUCHED — the scan never opened that
//     directory, and absence from a place you did not look is not evidence;
//   - it carries an `out_of_scope` event, so the timeline records WHY the scan
//     passed over it, rather than the row silently sitting still;
//   - the row under `sub/` — inside what was scanned, deterministic, and not
//     reported — DOES close. Without that control this test would also pass
//     for an implementation that simply stopped closing anything.
func TestSubPathScanNeverClosesOutsideScope(t *testing.T) {
	svc, repo := newLineageStack(t)
	root := targetTreeWithMarker(t)
	sub := filepath.Join(root, "sub")

	// Scan 1: the whole tree. Both findings are deterministic, so both obey
	// the absence rule and the only thing that can separate their fates is
	// scope.
	rootSource := targetLocalSource("src-root", root)
	inSub := detTargetFinding("fp-v1-sub", "fpv2-sub", "sub/a.py")
	inOther := detTargetFinding("fp-v1-other", "fpv2-other", "other/b.py")
	inOther.Title = "Unsafe deserialisation"
	inOther.Category = "CWE-502"

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-subpath-1"), rootSource, "cwe",
		evidenceResult(inSub, inOther)); err != nil {
		t.Fatalf("root scan: %v", err)
	}

	rows := lineageRowsAcross(t, repo, root)
	if len(rows) != 2 {
		t.Fatalf("root scan must create two lineage rows, got %d:%s", len(rows), summarizeRows(rows))
	}
	var subRow, otherRow model.FindingLineage
	for _, r := range rows {
		switch r.FingerprintV2 {
		case "fpv2-sub":
			subRow = r
		case "fpv2-other":
			otherRow = r
		}
	}
	if subRow.ID == "" || otherRow.ID == "" {
		t.Fatalf("expected one row per fingerprint_v2 after the root scan, got:%s", summarizeRows(rows))
	}

	// Scan 2: only `<root>/sub`. It reports neither tracked finding — the sub
	// one was genuinely fixed, the other one was never looked at.
	subSource := targetLocalSource("src-sub", sub)
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-subpath-2"), subSource, "cwe",
		evidenceResult(targetNoise("fp-v1-subscan-noise"))); err != nil {
		t.Fatalf("sub-path scan: %v", err)
	}

	// The row outside the scanned sub-tree is untouched, and says so.
	outside := reloadLineage(t, repo, otherRow.ID)
	if outside.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("a scan of %q never opened %q, so the finding there cannot have been observed "+
			"as repaired: expected %q, got %q",
			"sub", "other/b.py", model.LineageStatusOpen, outside.CurrentStatus)
	}
	if trans := transitionEvents(t, repo, otherRow.ID); len(trans) != 0 {
		t.Fatalf("a row outside the scanned sub-path must record no transition, got %v", trans)
	}
	if !hasEventType(eventTypesOf(t, repo, otherRow.ID), model.LineageEventOutOfScope) {
		t.Fatalf("expected an %q event recording that the scan could not have seen %q, got %v",
			model.LineageEventOutOfScope, outside.FilePath, eventTypesOf(t, repo, otherRow.ID))
	}
	if outside.SeenCount != subRow.SeenCount {
		t.Fatalf("a scan that never looked at the path did not see the finding either: "+
			"seen_count %d -> %d", subRow.SeenCount, outside.SeenCount)
	}

	// The control: inside the scanned sub-tree the deterministic rule is
	// unchanged. A test that merely stopped closing things would be a
	// regression, not a fix.
	inside := reloadLineage(t, repo, subRow.ID)
	if inside.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("a deterministic finding INSIDE the scanned sub-path and absent from its result "+
			"still closes: expected %q, got %q", model.LineageStatusFixed, inside.CurrentStatus)
	}

	// And the sub-path scan inherited the root's target, so it started no
	// second history for the same codebase (§7.2).
	if got := lineageRowsAcross(t, repo, root, sub); len(got) != 2 {
		t.Fatalf("a sub-path scan inherits its root's target key, so it must not create a second "+
			"lineage history: expected 2 rows across %q and %q, got %d:%s", root, sub, len(got), summarizeRows(got))
	}
}

// TestBranchSwitchDoesNotClose is scenario S24 — the case that shows grouping
// and closure are answers to two different questions.
//
// One repository, two checkouts: branch `main` and branch `feature/x`. A file
// that exists on `main` is not on `feature/x`. Both checkouts have the same
// remote, so both are the same TARGET — otherwise every branch would start its
// own history and a feature branch could never see the trunk's triage.
//
// But being the same target must not make a branch's absences authoritative
// over another branch's rows. A file that is missing because you are standing
// somewhere else has not been repaired; the commit that removed it may not
// exist. §7.4: grouping is per target, closure is per branch. A scan of
// another branch may CONFIRM a row, never close it.
//
// Both halves are asserted, because either alone is satisfiable by a wrong
// implementation: partition per branch would leave the `main` row untouched
// while re-duplicating every shared finding, and group-and-close would unify
// the history while closing the trunk's findings from a feature branch.
func TestBranchSwitchDoesNotClose(t *testing.T) {
	svc, repo := newLineageStack(t)

	// Two ingests of one repository. Git ingest gives each its own directory,
	// so the paths differ as well as the branches — exactly as in production.
	mainPath := "/tmp/vulture-sources/repo-main-1700000000/run-1"
	featPath := "/tmp/vulture-sources/repo-feat-1700009999/run-2"
	mainSource := targetSource("src-branch-main", mainPath, "main")
	featSource := targetSource("src-branch-feat", featPath, "feature/x")

	// Scan on `main`: one finding in a file both branches have, one in a file
	// only `main` has. Deterministic, so absence is what would close them.
	shared := detTargetFinding("fp-v1-shared-main", "fpv2-shared", "src/shared.py")
	onlyMain := detTargetFinding("fp-v1-onlymain", "fpv2-onlymain", "src/only_on_main.py")
	onlyMain.Title = "Hardcoded credential"
	onlyMain.Category = "CWE-798"

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-branch-1"), mainSource, "cwe",
		evidenceResult(shared, onlyMain)); err != nil {
		t.Fatalf("scan of main: %v", err)
	}

	rows := lineageRowsAcross(t, repo, mainPath)
	if len(rows) != 2 {
		t.Fatalf("the scan of main must create two lineage rows, got %d:%s", len(rows), summarizeRows(rows))
	}
	var sharedRow, onlyMainRow model.FindingLineage
	for _, r := range rows {
		switch r.FingerprintV2 {
		case "fpv2-shared":
			sharedRow = r
		case "fpv2-onlymain":
			onlyMainRow = r
		}
	}
	if sharedRow.ID == "" || onlyMainRow.ID == "" {
		t.Fatalf("expected one row per fingerprint_v2 after the main scan, got:%s", summarizeRows(rows))
	}

	// Scan on `feature/x`: the shared file is still there and still flagged;
	// `src/only_on_main.py` does not exist on this branch, so nothing is
	// reported for it. v1 differs (new checkout directory), v2 does not.
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-branch-2"), featSource, "cwe",
		evidenceResult(detTargetFinding("fp-v1-shared-feat", "fpv2-shared", "src/shared.py"))); err != nil {
		t.Fatalf("scan of feature/x: %v", err)
	}

	// Closure is per branch: the trunk's row is untouched.
	trunk := reloadLineage(t, repo, onlyMainRow.ID)
	if trunk.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("a file that is absent because the scan stood on %q has not been fixed on %q: "+
			"expected %q, got %q", "feature/x", "main",
			model.LineageStatusOpen, trunk.CurrentStatus)
	}
	if trans := transitionEvents(t, repo, onlyMainRow.ID); len(trans) != 0 {
		t.Fatalf("a scan of another branch may confirm a row but never close it, "+
			"yet it recorded %v", trans)
	}
	if trunk.RefNumber != onlyMainRow.RefNumber {
		t.Fatalf("the trunk row's VLT ref must be untouched by a scan of another branch: %d -> %d",
			onlyMainRow.RefNumber, trunk.RefNumber)
	}

	// Grouping is per target: the finding both branches see is ONE row, not
	// one per branch.
	all := lineageRowsAcross(t, repo, mainPath, featPath)
	if len(all) != 2 {
		t.Fatalf("two branches of one repository are one target, so the finding they share is one "+
			"lineage row: expected 2 rows in total, got %d:%s", len(all), summarizeRows(all))
	}
	carried := reloadLineage(t, repo, sharedRow.ID)
	if carried.SeenCount != 2 {
		t.Fatalf("the shared finding was reported by both branch scans: seen_count = %d, want 2",
			carried.SeenCount)
	}
	if carried.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("the shared finding was re-reported, so it stays %q — got %q",
			model.LineageStatusOpen, carried.CurrentStatus)
	}
}

// compile-time guard: the tests above drive the service through its interface,
// so a signature change to the closure entry point breaks them loudly rather
// than silently skipping the contract.
var _ = func(svc service.LineageService) {
	_ = svc.RecordScanOutcome
}
