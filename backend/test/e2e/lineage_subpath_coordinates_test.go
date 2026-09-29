//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §6.5 / §7.2 — one coordinate system for a relative file_path.
//
// Lineage rows keep a RELATIVE file_path in TARGET coordinates: relative to
// the target's root, the same coordinates `pruned_dirs` and the scan offset
// are expressed in. The agent's world is different — it reports a relative
// path, and resolves a requested `rel_path`, relative to the directory IT
// walked. For a root scan the two agree. For a sub-path scan (<root>/.vscode)
// they differ by the offset, and conflating them closes live findings:
//
//   - STORE. A sub-path scan reports `tasks.json`. Stored as-is, the next ROOT
//     scan asks the agent about `<root>/tasks.json`, which does not exist, and
//     `gone(file_missing)` marks the row fixed while the task still runs on
//     folder open.
//   - REQUEST. A root scan recorded `.vscode/tasks.json`. Sent as-is to a
//     sub-path scan, the agent looks for `<root>/.vscode/.vscode/tasks.json`,
//     with the same result.
//
// THE CONTRACT. A relative path from a sub-path scan is stored under the
// scan's offset, and a relative row path is sent to the agent with the offset
// removed. A row outside the scanned sub-tree is not requested at all: the
// agent never opened that directory and has nothing to verify.

// subPathTarget lays out a marker-resolved target with a .vscode sub-tree and
// returns the root source and the .vscode sub-path source.
func subPathTarget(t *testing.T) (root, sub *model.Source) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".vscode"), 0o700); err != nil {
		t.Fatalf("mkdir .vscode: %v", err)
	}
	root = lineageTestSource(dir)
	sub = lineageTestSource(filepath.Join(dir, ".vscode"))
	sub.ID = "src-lineage-e2e-sub"
	return root, sub
}

func requestedRelPath(t *testing.T, reqs map[string]*model.LineageChecksRequest, lineageID string) (string, bool) {
	t.Helper()
	req := reqs["cwe"]
	if req == nil {
		return "", false
	}
	for _, r := range req.Rows {
		if r.LineageID == lineageID {
			return r.RelPath, true
		}
	}
	return "", false
}

// TestSubPathFindingIsStoredInTargetCoordinates is the STORE half, followed
// through to the root scan that would otherwise close the row.
func TestSubPathFindingIsStoredInTargetCoordinates(t *testing.T) {
	svc, repo := newLineageStack(t)
	root, sub := subPathTarget(t)
	const fp = "fp-llm-subpath-store"

	f := llmLineageFinding(fp)
	f.FilePath = "tasks.json" // as the agent walking <root>/.vscode reports it
	seedLLMLineage(t, svc, repo, sub, []model.Finding{f})
	row := lineageRowOf(t, repo, fp, sub.Path)

	if row.FilePath != ".vscode/tasks.json" {
		t.Fatalf("a relative path from a sub-path scan must be stored in target "+
			"coordinates: file_path = %q, want %q", row.FilePath, ".vscode/tasks.json")
	}
	rel, ok := requestedRelPath(t, svc.PendingChecks(root, []string{"cwe"}), row.ID)
	if !ok || rel != ".vscode/tasks.json" {
		t.Fatalf("a root scan must ask about %q, got %q (requested=%v)", ".vscode/tasks.json", rel, ok)
	}
	rel, ok = requestedRelPath(t, svc.PendingChecks(sub, []string{"cwe"}), row.ID)
	if !ok || rel != "tasks.json" {
		t.Fatalf("a .vscode scan must ask about %q, got %q (requested=%v)", "tasks.json", rel, ok)
	}
}

// TestRootFindingIsRequestedRelativeToSubPath is the REQUEST half: a row the
// root scan recorded is asked about in the sub-path agent's own coordinates.
func TestRootFindingIsRequestedRelativeToSubPath(t *testing.T) {
	svc, repo := newLineageStack(t)
	root, sub := subPathTarget(t)
	const fp = "fp-llm-root-request"

	f := llmLineageFinding(fp) // FilePath .vscode/tasks.json, root coordinates
	seedLLMLineage(t, svc, repo, root, []model.Finding{f})
	row := lineageRowOf(t, repo, fp, root.Path)

	if row.FilePath != ".vscode/tasks.json" {
		t.Fatalf("a root scan's relative path is already in target coordinates: "+
			"file_path = %q, want %q", row.FilePath, ".vscode/tasks.json")
	}
	rel, ok := requestedRelPath(t, svc.PendingChecks(sub, []string{"cwe"}), row.ID)
	if !ok || rel != "tasks.json" {
		t.Fatalf("a .vscode scan must ask about %q, got %q (requested=%v)", "tasks.json", rel, ok)
	}
}

// TestRowOutsideSubPathIsNotRequested: the sub-path agent never walks src/,
// so it must not be handed a row there to "verify".
func TestRowOutsideSubPathIsNotRequested(t *testing.T) {
	svc, repo := newLineageStack(t)
	root, sub := subPathTarget(t)
	const fp = "fp-llm-outside-subpath"

	f := llmLineageFinding(fp)
	f.FilePath = "src/server.js"
	seedLLMLineage(t, svc, repo, root, []model.Finding{f})
	row := lineageRowOf(t, repo, fp, root.Path)

	if _, ok := requestedRelPath(t, svc.PendingChecks(root, []string{"cwe"}), row.ID); !ok {
		t.Fatal("precondition: a root scan must request the row")
	}
	if rel, ok := requestedRelPath(t, svc.PendingChecks(sub, []string{"cwe"}), row.ID); ok {
		t.Fatalf("a row outside the scanned sub-tree must not be requested, got rel_path %q", rel)
	}
}
