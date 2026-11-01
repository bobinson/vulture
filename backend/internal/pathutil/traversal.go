// Package pathutil holds the backend's shared path-safety helpers: the
// canonical `..` traversal check (feature 0052), the source-root confinement
// every server-side local path goes through, its one lexical containment
// predicate Within, and the local-path policy (feature 0102).
package pathutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxConfinedPathBytes is the longest path confinement looks at: Linux
// PATH_MAX. The kernel refuses anything longer, so no reachable path is lost,
// and a hostile path costs at most this much work.
const MaxConfinedPathBytes = 4096

// ErrNotPermitted is every confinement refusal: a path that is relative, too
// long or holds a ".." segment, that is spelled outside the root, that does
// not resolve, or that resolves outside the root, and every root fault
// (ErrRootUnavailable). A refusal carries its cause as text only, so a
// failure to resolve the ROOT can never be mistaken for the path's own
// absence.
var ErrNotPermitted = errors.New("path not permitted")

// ErrRootUnavailable is a root fault: the root itself does not resolve, is
// not a directory, or cannot be opened by the server (os.Root needs read
// permission on it, so a root the server can only traverse cannot confine).
// It is the operator's to fix and says nothing about the requested path: it
// is reported for every path of a confinable shape, inside the root or not.
// Its text reaches clients and audit records, the same for every path.
var ErrRootUnavailable = errors.New("source root unavailable")

// ErrNotDir reports a confined path that exists but is not a directory.
var ErrNotDir = errors.New("not a directory")

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

// EnsureWithinRoot returns the resolved absolute form of path, or an error
// wrapping ErrNotPermitted when it is not confined to root. root == "" means
// no confinement: the path is returned unchanged. With a root, path must be
// absolute, at most MaxConfinedPathBytes, free of "..", and spelled under the
// root (its absolute or resolved spelling); its deepest existing ancestor's
// symlinks are then resolved, so a symlinked parent cannot escape (0065),
// and a missing tail is judged lexically.
func EnsureWithinRoot(root, path string) (string, error) {
	if root == "" {
		return path, nil
	}
	_, resolved, err := confine(root, path)
	return resolved, err
}

// ResolveDirWithinRoot returns nil when path is an existing directory
// confined to root. root == "" stats path as given, keeping the stat's error
// class (fs.ErrNotExist, fs.ErrPermission) or returning ErrNotDir. With a root
// the path is confined first, and the resolved result is stat'd through
// os.Root, so a link swapped in after confinement cannot make the stat
// describe anything outside the root.
func ResolveDirWithinRoot(root, path string) error {
	if root == "" {
		return requireDir(os.Stat(path))
	}
	realRoot, resolved, err := confine(root, path)
	if err != nil {
		return err
	}
	return statInRoot(realRoot, resolved)
}

// Within reports whether p is lexically inside base. It does not resolve
// symlinks: pass paths that are already resolved, or that have passed
// RejectTraversal. A user-supplied path goes through EnsureWithinRoot or
// ResolveDirWithinRoot instead.
//
// It has filepath.Rel semantics and fails closed: false when either side is
// empty, and false for a mixed absolute and relative pair, so a relative p
// never passes against an absolute base.
func Within(base, p string) bool {
	if base == "" || p == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(p))
	return err == nil && !escapes(rel)
}

// escapes reports whether a filepath.Rel result leaves its base.
func escapes(rel string) bool { return rel == ".." || strings.HasPrefix(rel, "../") }

// confine resolves path under root and returns the resolved root and path.
// In order: the path's shape, the root, the lexical pre-check (no syscall on
// the path yet), then the ancestor resolution and the containment of its
// result. Every failure wraps ErrNotPermitted.
func confine(root, path string) (realRoot, resolved string, err error) {
	if err = checkConfinable(path); err != nil {
		return "", "", err
	}
	absRoot, realRoot, err := resolveRoot(root)
	if err != nil {
		return "", "", err
	}
	if !lexicallyInside(absRoot, realRoot, path) {
		return "", "", fmt.Errorf("%w: spelled outside the source root", ErrNotPermitted)
	}
	resolved, err = resolveInside(realRoot, path)
	return realRoot, resolved, err
}

// checkConfinable is the shape a path must have before it is compared with a
// root: absolute, at most MaxConfinedPathBytes, and with no ".." segment in
// the RAW spelling. ".." is refused rather than cleaned because the kernel
// applies it after resolving the link before it (R/lnk/../x is
// <target of lnk>/../x), which a lexical clean cannot know.
func checkConfinable(path string) error {
	if len(path) > MaxConfinedPathBytes || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: not an absolute path of at most %d bytes", ErrNotPermitted, MaxConfinedPathBytes)
	}
	if RejectTraversal(path) != nil {
		return fmt.Errorf("%w: contains a .. segment", ErrNotPermitted)
	}
	return nil
}

// resolveRoot returns the root in its absolute spelling (so a relative root
// is compared as an absolute path, never as a mixed pair) and with every
// symlink resolved, once the server has opened it as a directory, as
// statInRoot will. Every failure is a root fault, found before the path is
// looked at, so every entry point reports a broken root the same way.
func resolveRoot(root string) (absRoot, realRoot string, err error) {
	if absRoot, err = filepath.Abs(root); err == nil {
		realRoot, err = filepath.EvalSymlinks(absRoot)
	}
	if err == nil {
		err = openable(realRoot)
	}
	if err != nil {
		return "", "", rootFault(err)
	}
	return absRoot, realRoot, nil
}

// openable returns nil when the server can open dir as an os.Root (a
// directory it may read), else why not.
func openable(dir string) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return r.Close()
}

// rootFault marks a failure of the root itself: a refusal (ErrNotPermitted)
// and ErrRootUnavailable, with its cause as text only.
func rootFault(cause error) error {
	return fmt.Errorf("%w: %w: %v", ErrNotPermitted, ErrRootUnavailable, cause)
}

// lexicallyInside reports whether p is spelled under the root, in either its
// absolute or its resolved spelling. It makes no syscall on p, so a path
// spelled outside the root is refused before anything there is looked at,
// including an outside spelling that links INTO the root.
func lexicallyInside(absRoot, realRoot, p string) bool {
	return Within(absRoot, p) || Within(realRoot, p)
}

// resolveInside resolves path (already confinable and spelled under the root)
// and requires the result to stay under realRoot, so an in-root link that
// points out is refused.
func resolveInside(realRoot, path string) (string, error) {
	resolved, err := resolveExistingAncestor(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if !Within(realRoot, resolved) {
		return "", fmt.Errorf("%w: resolves outside the source root", ErrNotPermitted)
	}
	return resolved, nil
}

// resolveExistingAncestor resolves the deepest existing prefix of abs (clean
// and absolute) and re-appends the rest lexically. The prefix is found by a
// binary search over components, which is sound because Lstat success is
// prefix-closed: an entry exists only if every ancestor resolves to a
// directory. So a 4 KB path costs about a dozen Lstat calls, not one walk per
// component. A prefix that exists but does not resolve (a dangling link, a
// loop) is refused, never treated as absent.
func resolveExistingAncestor(abs string) (string, error) {
	ends := prefixEnds(abs)
	n := 1 + sort.Search(len(ends)-1, func(i int) bool {
		_, err := os.Lstat(abs[:ends[i+1]])
		return err != nil
	})
	head, err := filepath.EvalSymlinks(abs[:ends[n-1]])
	if err != nil {
		return "", fmt.Errorf("%w: unresolvable link: %v", ErrNotPermitted, err)
	}
	return filepath.Join(head, abs[ends[n-1]:]), nil
}

// prefixEnds returns where each prefix of abs ends, shortest first: "/",
// "/a", "/a/b", ..., abs. abs must be clean and absolute.
func prefixEnds(abs string) []int {
	ends := make([]int, 1, strings.Count(abs, "/")+1)
	ends[0] = 1
	for i := 1; i < len(abs); i++ {
		if abs[i] == '/' {
			ends = append(ends, i)
		}
	}
	if len(abs) > 1 {
		ends = append(ends, len(abs))
	}
	return ends
}

// statInRoot stats resolved, a path confine returned, through os.Root at
// realRoot. The relative name comes from the RESOLVED path: os.Root refuses
// an absolute symlink even when it points inside the root, so the request
// spelling (current -> /root/releases/v2) would fail there.
func statInRoot(realRoot, resolved string) error {
	rel, err := filepath.Rel(realRoot, resolved)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotPermitted, err)
	}
	r, err := os.OpenRoot(realRoot)
	if err != nil {
		return rootFault(err)
	}
	defer r.Close()
	return requireDir(r.Stat(rel))
}

// requireDir turns a stat result into nil for a directory, ErrNotDir for
// anything else, or the stat's own error.
func requireDir(info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrNotDir
	}
	return nil
}
