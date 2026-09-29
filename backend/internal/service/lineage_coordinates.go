package service

import (
	"path/filepath"
	"strings"
)

// Feature 0091 §6.5 / §7.2 — the two coordinate systems a relative file_path
// can be in, and the only two places a path crosses between them.
//
// A lineage row's relative file_path is in TARGET coordinates: relative to the
// target root, the same system `pruned_dirs` and the scan offset use. The
// agent's is relative to the directory IT walked, which for a sub-path scan is
// the target root plus the offset. Crossing without converting closes live
// findings: a `.vscode` scan's `tasks.json` becomes `<root>/tasks.json` to the
// next root scan, a root scan's `.vscode/tasks.json` becomes
// `.vscode/.vscode/tasks.json` to the next `.vscode` scan, and either way the
// agent answers `gone(file_missing)`.
//
// An absolute path is left alone in both directions: it names one file
// whatever the scan root, and `scanScope.place` already decides whether it is
// under this scan.

// targetPath converts a path the agent reported into target coordinates.
func targetPath(target TargetIdentity, reported string) string {
	if reported == "" || isAbsPath(reported) {
		return reported
	}
	return joinRel(normalizeRel(target.Offset), normalizeRel(reported))
}

// agentPath converts a row's stored path into the coordinates of the agent
// scanning at target.Offset. It reports false for a relative path outside the
// scanned sub-tree: the agent never walked there and has nothing to verify.
func agentPath(target TargetIdentity, stored string) (string, bool) {
	offset := normalizeRel(target.Offset)
	if offset == "" || stored == "" || isAbsPath(stored) {
		return stored, true
	}
	rel := normalizeRel(stored)
	if rel == offset {
		return "", true
	}
	if strings.HasPrefix(rel, offset+"/") {
		return strings.TrimPrefix(rel, offset+"/"), true
	}
	return "", false
}

func isAbsPath(p string) bool {
	return strings.HasPrefix(filepath.ToSlash(strings.TrimSpace(p)), "/")
}
