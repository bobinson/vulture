// Package pathutil is a tiny grab-bag for path-safety helpers shared
// across the backend. Today (feature 0052) it hosts the single
// canonical `..` traversal check so plugin-registry and plugin-supervisor
// don't each carry their own copy.
package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// RejectTraversal returns a non-nil error if `p` contains any `..`
// path segment (after Clean). Bare `.` components are tolerated —
// they are a no-op, not a traversal.
//
// The check is purely lexical: it does not stat the path or resolve
// symlinks. Callers that also need symlink rejection should compose
// this with pluginregistry.RejectSymlink.
func RejectTraversal(p string) error {
	cleaned := filepath.Clean(p)
	// Quick win: Clean collapses interior `..`. If Clean produced a
	// segment containing `..`, the original path tried to escape.
	for _, seg := range strings.Split(cleaned, string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("path %q contains .. traversal", p)
		}
	}
	// Defence in depth: even if Clean simplified them away, reject
	// the raw form so the error message stays close to the input.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("path %q contains .. traversal", p)
		}
	}
	return nil
}

// EnsureWithinRoot returns the resolved absolute form of path and an error if
// it is not inside root. root=="" means no confinement. Resolves the deepest
// existing ancestor's symlinks (0065 §M10) so a symlinked parent cannot escape.
func EnsureWithinRoot(root, path string) (string, error) {
	if root == "" {
		return path, nil
	}
	realRoot, err := filepath.EvalSymlinks(mustAbs(root))
	if err != nil {
		return "", fmt.Errorf("resolve source root: %w", err)
	}
	resolved, err := resolveExistingAncestor(mustAbs(path))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(realRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes source root", path)
	}
	return resolved, nil
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// resolveExistingAncestor EvalSymlinks the deepest existing prefix of abs and
// re-appends the non-existent tail lexically.
func resolveExistingAncestor(abs string) (string, error) {
	cur, tail := abs, []string(nil)
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				real = filepath.Join(real, tail[i])
			}
			return real, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("no existing ancestor for %q", abs)
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}
