package repository

import (
	"testing"
	"time"
)

// THE AGGREGATE'S FIELD IS CALLED rel_path AND IT SERVES ABSOLUTE HOST PATHS.
//
// finding_lineage.file_path holds whichever form the reporting tier emitted —
// deterministic skills report an absolute path, the LLM tier a relative one
// (feature 0079 A1 measured this and chose, deliberately, to canonicalise the
// dedup KEY and never the stored value: the stored path also has to resolve on
// disk for the L5 judge's file signature).
//
// The report is the wrong place to keep that split. Measured live on one
// target: 36 of 46 rel_path values were absolute, so the UI printed the
// operator's home directory for deterministic findings and a clean relative
// path for LLM ones, in the same column, in the same table.
//
// Normalising here is display-only: nothing is written back, no fingerprint
// moves, and a row whose path cannot be placed under its own source root is
// returned unchanged rather than mangled.
func TestAggregateRelPathIsRelativeToTheRowsSource(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, filePath, sourcePath, want string
	}{
		{
			name:       "deterministic tier absolute path is made relative",
			filePath:   "/home/user/danger/blu-simulator/server/middleware/requestContext.js",
			sourcePath: "/home/user/danger/blu-simulator",
			want:       "server/middleware/requestContext.js",
		},
		{
			name:       "LLM tier relative path is already correct and untouched",
			filePath:   "server/middleware/requestContext.js",
			sourcePath: "/home/user/danger/blu-simulator",
			want:       "server/middleware/requestContext.js",
		},
		{
			name:       "a sub-path scan resolves against its own source",
			filePath:   "/home/user/danger/blu-simulator/.vscode/tasks.json",
			sourcePath: "/home/user/danger/blu-simulator/.vscode",
			want:       "tasks.json",
		},
		{
			name:       "the docker mount prefix is stripped even when source is unknown",
			filePath:   "/mnt/source/server/app.js",
			sourcePath: "",
			want:       "server/app.js",
		},
		{
			name:       "a path outside its source root is left alone rather than mangled",
			filePath:   "/etc/passwd",
			sourcePath: "/home/user/danger/blu-simulator",
			want:       "/etc/passwd",
		},
		{
			name:       "an empty path stays empty",
			filePath:   "",
			sourcePath: "/home/user/danger/blu-simulator",
			want:       "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := newAggregateRow(aggregateRowScan{
				id: "l1", refNumber: 7, severity: "high", category: "CWE-20",
				title: "t", filePath: tc.filePath, sourcePath: tc.sourcePath,
				lineStart: 4, provenance: "skill", seenCount: 1, status: "open",
				firstFoundAt: now, latestFoundAt: now,
			})
			if row.RelPath != tc.want {
				t.Errorf("rel_path = %q, want %q (file_path %q under source %q)",
					row.RelPath, tc.want, tc.filePath, tc.sourcePath)
			}
		})
	}
}

// The two path forms must collapse to ONE rel_path, or the report still shows
// one weakness as two differently-named rows.
func TestAggregateRelPathCollapsesTheTierSplit(t *testing.T) {
	now := time.Now().UTC()
	mk := func(fp string) string {
		return newAggregateRow(aggregateRowScan{
			id: "l", severity: "medium", category: "CWE-20", title: "t",
			filePath: fp, sourcePath: "/srv/app", lineStart: 4, provenance: "skill",
			seenCount: 1, status: "open", firstFoundAt: now, latestFoundAt: now,
		}).RelPath
	}
	det, llm := mk("/srv/app/src/a.js"), mk("src/a.js")
	if det != llm {
		t.Fatalf("the same file reported by the two tiers must render one rel_path: %q vs %q", det, llm)
	}
}

// ONE REPORT, ONE COORDINATE SYSTEM.
//
// The aggregate spans every scan of a codebase, including sub-path scans. A
// row recorded by a scan of `<root>/.vscode` has that directory as its
// source_path, so relativising against the ROW's own source renders it
// `tasks.json` while a root-scanned row beside it renders
// `server/controllers/auth.js`. Both are "relative", and the reader cannot
// tell that the first one lives in `.vscode/`. Measured on blu-simulator the
// moment per-row relativisation landed: VLT-92190 and VLT-92561 rendered as
// bare `tasks.json`.
//
// The report is per TARGET, so the target's root is the coordinate system.
func TestAggregateRelPathIsRelativeToTheTargetRootNotTheRowsSubPath(t *testing.T) {
	now := time.Now().UTC()
	const targetRoot = "/home/user/danger/blu-simulator"
	mk := func(filePath, sourcePath string) string {
		return newAggregateRow(aggregateRowScan{
			id: "l", severity: "critical", category: "CWE-506", title: "t",
			filePath: filePath, sourcePath: sourcePath, targetRoot: targetRoot,
			lineStart: 7, provenance: "skill", seenCount: 1, status: "open",
			firstFoundAt: now, latestFoundAt: now,
		}).RelPath
	}
	// Recorded by a scan that stood on the sub-directory.
	if got := mk(targetRoot+"/.vscode/tasks.json", targetRoot+"/.vscode"); got != ".vscode/tasks.json" {
		t.Errorf("a sub-path scan's row must still be addressed from the target root: got %q, want %q",
			got, ".vscode/tasks.json")
	}
	// Recorded by a scan that stood on the root.
	if got := mk(targetRoot+"/server/controllers/auth.js", targetRoot); got != "server/controllers/auth.js" {
		t.Errorf("a root-scanned row is unchanged: got %q", got)
	}
	// The LLM tier's already-relative path is relative to ITS scan's root, so a
	// sub-path scan's relative path still needs the offset restored.
	if got := mk("tasks.json", targetRoot+"/.vscode"); got != ".vscode/tasks.json" {
		t.Errorf("a relative path from a sub-path scan must be re-rooted at the target: got %q, want %q",
			got, ".vscode/tasks.json")
	}
	// A row from another mount cannot be placed under this target root; its own
	// source still relativises it rather than leaving a raw absolute path.
	if got := mk("/mnt/source/server/app.js", "/mnt/source"); got != "server/app.js" {
		t.Errorf("another mount's row falls back to its own source: got %q", got)
	}
}
