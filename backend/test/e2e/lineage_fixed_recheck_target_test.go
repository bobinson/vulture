//go:build e2e

package e2e

import (
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §6.3 / S11 — the bounded fixed-row re-check must follow TARGET
// identity, like every other read in the pass.
//
// THE DEFECT. `boundedFixedRows` read `GetRecentlyFixedBySourcePath(source.Path)`
// while its sibling `activeRows` had moved to `ActiveByTarget` plus the legacy
// bridge. `source_path` is written once, at first sighting, and nothing ever
// rewrites it — so a row closed while the tree was mounted at /mnt/source/proj
// is never re-checked by a native scan of /home/x/proj. For a git source it is
// worse than "after a mount change": every ingest clones into a fresh
// directory, so the fallback is dead from the first scan onward and deployment
// mode D (`vulture scan <git-url>` in CI) never re-checks a closed finding at
// all.
//
// That is D3 — "lineage is partitioned by the exact source_path string" — the
// root cause 0091 exists to remove, surviving in the one read that did not
// move with the others.
func TestFixedRowIsRecheckedAcrossMounts(t *testing.T) {
	svc, repo := newLineageStack(t)

	const remote = "https://github.com/acme/recheck.git"
	docker := &model.Source{ID: "src-docker", Type: model.SourceTypeGit,
		Path: "/mnt/source/recheck", URL: remote, GitRemoteURL: remote}
	native := &model.Source{ID: "src-native", Type: model.SourceTypeGit,
		Path: "/home/x/recheck", URL: remote, GitRemoteURL: remote}

	// Scan 1, under the docker mount: the LLM tier raises the finding.
	llm := llmTargetFinding("fp-recheck-v1", "fpv2-recheck", "src/auth.go")
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-recheck-1"), docker, "cwe",
		evidenceResult(llm)); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	row := lineageRowOf(t, repo, "fp-recheck-v1", "/mnt/source/recheck")

	// Scan 2, still under the docker mount: the agent reads the file and the
	// quote is gone, so the row closes on EVIDENCE — the only way an LLM row
	// may close.
	gone := evidenceResult(targetNoise("fp-recheck-noise-1"))
	gone.LineageChecks = []model.LineageCheck{{
		LineageID: row.ID, Outcome: model.LineageOutcomeGone, Reason: "not_found",
	}}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-recheck-2"), docker, "cwe", gone); err != nil {
		t.Fatalf("closing scan: %v", err)
	}
	if closed := reloadLineage(t, repo, row.ID); closed.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("setup: the evidence check said the quote is gone, expected %q, got %q",
			model.LineageStatusFixed, closed.CurrentStatus)
	}

	// Scan 3 stands on the NATIVE checkout of the same repository. The row it
	// must reconsider was closed under the other mount.
	if got := checkRequestIDs(t, svc, native); !containsID(got, row.ID) {
		t.Fatalf("a fixed LLM row of THIS target must be re-checked whatever mount closed it: "+
			"PendingChecks returned %v, want it to contain %s", got, row.ID)
	}

	// And the check actually applies: the code came back, so the row regresses.
	back := evidenceResult(targetNoise("fp-recheck-noise-2"))
	back.LineageChecks = []model.LineageCheck{{
		LineageID: row.ID, Outcome: model.LineageOutcomeConfirmed, Reason: "exact",
	}}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-recheck-3"), native, "cwe", back); err != nil {
		t.Fatalf("native rescan: %v", err)
	}
	again := reloadLineage(t, repo, row.ID)
	if again.CurrentStatus != model.LineageStatusRegression {
		t.Fatalf("the agent found the stored quote again, so the finding is back: expected %q, got %q",
			model.LineageStatusRegression, again.CurrentStatus)
	}
}

// TestFixedRowRecheckStillWorksOnTheSameMount is the control: the window and
// its bound are unchanged, so this fix cannot be satisfied by asking about
// every row ever closed.
func TestFixedRowRecheckStillWorksOnTheSameMount(t *testing.T) {
	svc, repo := newLineageStack(t)
	source := targetLocalSource("src-same", "/home/x/same")

	llm := llmTargetFinding("fp-same-v1", "fpv2-same", "src/auth.go")
	det := detTargetFinding("fp-same-det", "fpv2-same-det", "src/other.go")
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-same-1"), source, "cwe",
		evidenceResult(llm, det)); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	llmRow := lineageRowOf(t, repo, "fp-same-v1", "/home/x/same")
	detRow := lineageRowOf(t, repo, "fp-same-det", "/home/x/same")

	gone := evidenceResult(targetNoise("fp-same-noise"))
	gone.LineageChecks = []model.LineageCheck{{
		LineageID: llmRow.ID, Outcome: model.LineageOutcomeGone, Reason: "not_found",
	}}
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-same-2"), source, "cwe", gone); err != nil {
		t.Fatalf("closing scan: %v", err)
	}

	ids := checkRequestIDs(t, svc, source)
	if !containsID(ids, llmRow.ID) {
		t.Fatalf("the fixed LLM row is inside the re-check window: %v", ids)
	}
	// A deterministic row is caught by the ordinary present-in-result path and
	// has no quote to verify, so it is never asked about.
	if containsID(ids, detRow.ID) {
		t.Fatalf("a deterministic row must never enter the evidence request: %v", ids)
	}
}

func checkRequestIDs(t *testing.T, svc lineageChecker, source *model.Source) []string {
	t.Helper()
	req := svc.PendingChecks(source, []string{"cwe"})["cwe"]
	if req == nil {
		return nil
	}
	out := make([]string, 0, len(req.Rows))
	for _, r := range req.Rows {
		out = append(out, r.LineageID)
	}
	return out
}

// lineageChecker is the one method these two tests need, named so the helper
// does not drag the whole service interface into its signature.
type lineageChecker interface {
	PendingChecks(*model.Source, []string) map[string]*model.LineageChecksRequest
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
