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
