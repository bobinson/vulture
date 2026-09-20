//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §7.2 / S14, on the branch that actually fires in production.
//
// TestSubPathScanNeverClosesOutsideScope builds its tree with `package.json`
// and no remote, so it exercises the MARKER branch of ResolveTarget — the one
// that always computed an Offset. Step 1 of §7.1 is the git-REMOTE branch, and
// `gitutil.GetInfo` answers with the repository remote from any directory
// inside a checkout, so that branch is what a sub-path scan of any real
// repository takes. It returned the SCANNED path as Root and no Offset at all,
// which makes `underOffset` answer true for every root-relative path and
// `scanScope.exclusion` return "" — so the pass fell straight through to
// closeDeterministic for a row the scan never looked at.
//
// The assertions are the ones S14 already makes, plus the control that keeps
// the test honest: the row INSIDE the scanned sub-tree still closes.
func TestGitRemoteSubPathScanNeverClosesOutsideScope(t *testing.T) {
	svc, repo := newLineageStack(t)
	root := gitRemoteTargetTree(t)
	sub := filepath.Join(root, "sub")

	rootSource := gitRemoteSource("src-git-root", root)
	inSub := detTargetFinding("fp-git-sub", "fpv2-git-sub", "sub/a.py")
	inOther := detTargetFinding("fp-git-other", "fpv2-git-other", "other/b.py")
	inOther.Title = "Unsafe deserialisation"
	inOther.Category = "CWE-502"

	if err := svc.RecordScanOutcome(lineageTestAudit("audit-gitsub-1"), rootSource, "cwe",
		evidenceResult(inSub, inOther)); err != nil {
		t.Fatalf("root scan: %v", err)
	}

	rows := lineageRowsAcross(t, repo, root)
	var subRow, otherRow model.FindingLineage
	for _, r := range rows {
		switch r.FingerprintV2 {
		case "fpv2-git-sub":
			subRow = r
		case "fpv2-git-other":
			otherRow = r
		}
	}
	if subRow.ID == "" || otherRow.ID == "" {
		t.Fatalf("expected one row per fingerprint_v2 after the root scan, got:%s", summarizeRows(rows))
	}

	// Scan 2 stands in `<root>/sub` and reports neither tracked finding. It
	// carries the SAME remote, because git reports the checkout's remote from
	// any directory inside it — which is exactly how a sub-path ingest of a
	// real repository is recorded.
	subSource := gitRemoteSource("src-git-sub", sub)
	if err := svc.RecordScanOutcome(lineageTestAudit("audit-gitsub-2"), subSource, "cwe",
		evidenceResult(targetNoise("fp-git-subscan-noise"))); err != nil {
		t.Fatalf("sub-path scan: %v", err)
	}

	outside := reloadLineage(t, repo, otherRow.ID)
	if outside.CurrentStatus != model.LineageStatusOpen {
		t.Fatalf("a scan of %q never opened %q, so it cannot have observed a repair there: "+
			"expected %q, got %q", sub, "other/b.py", model.LineageStatusOpen, outside.CurrentStatus)
	}
	if trans := transitionEvents(t, repo, otherRow.ID); len(trans) != 0 {
		t.Fatalf("a row outside the scanned sub-path must record no transition, got %v", trans)
	}
	if !hasEventType(eventTypesOf(t, repo, otherRow.ID), model.LineageEventOutOfScope) {
		t.Fatalf("expected an %q event recording why the scan passed over %q, got %v",
			model.LineageEventOutOfScope, outside.FilePath, eventTypesOf(t, repo, otherRow.ID))
	}

	// The control: inside the scanned sub-tree the deterministic rule is
	// unchanged, so this test cannot be satisfied by closing nothing at all.
	inside := reloadLineage(t, repo, subRow.ID)
	if inside.CurrentStatus != model.LineageStatusFixed {
		t.Fatalf("a deterministic finding INSIDE the scanned sub-path and absent from its result "+
			"still closes: expected %q, got %q", model.LineageStatusFixed, inside.CurrentStatus)
	}
}

// gitRemoteTargetTree is targetTreeWithMarker with a real `.git` directory, so
// ResolveTarget's remote branch has an ancestor to resolve the root at. The
// remote itself is supplied on the Source (that is how ingest records it); the
// `.git` directory is what the offset climb needs.
func gitRemoteTargetTree(t *testing.T) string {
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
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Skipf("git init unavailable: %v (%s)", err, out)
	}
	write("sub/a.py", "import os\nos.system(cmd)\n")
	write("other/b.py", "import pickle\npickle.loads(blob)\n")
	return root
}

func gitRemoteSource(id, path string) *model.Source {
	s := targetLocalSource(id, path)
	s.GitRemoteURL = "git@github.com:acme/gitscope.git"
	return s
}
