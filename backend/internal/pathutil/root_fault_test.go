package pathutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A source root the server cannot use (feature 0102): missing or unmounted,
// not a directory, or one the server cannot open. Confinement opens the root
// (os.Root), which needs read permission on it, so a root the server can only
// traverse cannot confine anything. That is the operator's fault, not the
// requested path's: every entry point reports it as ErrRootUnavailable for
// any path, so ingest (ResolveDir), browse (EnsureWithinRoot) and dispatch
// (Recheck) agree. It stays a refusal (ErrNotPermitted), so a caller that
// knows only that fails closed, and its cause names the root, never the path.

// brokenRoot is a root the server cannot use, with a path spelled inside it.
type brokenRoot struct {
	root, inside string
}

// brokenRoots returns one broken root of each kind. The permission cases are
// left out when the test runs as root, which ignores the mode.
func brokenRoots(t *testing.T) map[string]brokenRoot {
	t.Helper()
	base := t.TempDir()
	gone := filepath.Join(base, "gone")
	file := confineFile(t, filepath.Join(base, "file"))
	dangling := confineSymlink(t, gone, filepath.Join(base, "dangling"))
	roots := map[string]brokenRoot{
		"missing":       {gone, filepath.Join(gone, "project")},
		"a file":        {file, filepath.Join(file, "project")},
		"dangling link": {dangling, filepath.Join(dangling, "project")},
	}
	if os.Geteuid() == 0 {
		return roots
	}
	for _, c := range []struct {
		name, dir string
		mode      os.FileMode
	}{{"search-only (0100)", "search-only", 0o100}, {"no access (0000)", "no-access", 0}} {
		root := filepath.Join(base, c.dir)
		roots[c.name] = brokenRoot{root, confineMkdir(t, filepath.Join(root, "project"))}
		confineChmod(t, root, c.mode)
	}
	return roots
}

// confineChmod sets dir's mode and restores 0755 at cleanup, so the temp
// tree can be removed.
func confineChmod(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// wantRootFault fails unless err is a root fault: ErrRootUnavailable, still
// a refusal, never read as the path's own absence or permission, and with a
// cause that does not name the requested path.
func wantRootFault(t *testing.T, what, path string, err error) {
	t.Helper()
	if !isRootFault(err) {
		t.Errorf("%s = %v; want ErrRootUnavailable and ErrNotPermitted", what, err)
	}
	if readsAsPathError(err) {
		t.Errorf("%s = %v; a root fault must not read as the path's own error class", what, err)
	}
	if errNames(err, path) {
		t.Errorf("%s = %v; the cause must not name the requested path", what, err)
	}
}

// isRootFault reports whether err is ErrRootUnavailable and still a refusal.
func isRootFault(err error) bool {
	return errors.Is(err, ErrRootUnavailable) && errors.Is(err, ErrNotPermitted)
}

// readsAsPathError reports whether err would read as the path's own absence
// or permission.
func readsAsPathError(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}

// errNames reports whether err's text contains s.
func errNames(err error, s string) bool {
	return err != nil && strings.Contains(err.Error(), s)
}

// TestRootFault_EveryEntryPointAgrees: a broken root is reported the same way
// by ingest, browse and dispatch, for a path inside it and one outside it.
func TestRootFault_EveryEntryPointAgrees(t *testing.T) {
	outside := t.TempDir()
	for name, b := range brokenRoots(t) {
		t.Run(name, func(t *testing.T) {
			p := NewLocalSources(b.root, false, false)
			for _, path := range []string{b.inside, outside} {
				_, err := EnsureWithinRoot(b.root, path)
				wantRootFault(t, "EnsureWithinRoot "+path, path, err)
				wantRootFault(t, "ResolveDirWithinRoot "+path, path, ResolveDirWithinRoot(b.root, path))
				wantRootFault(t, "ResolveDir "+path, path, p.ResolveDir(path))
				wantRootFault(t, "Recheck "+path, path, p.Recheck(path))
			}
		})
	}
}

// TestRootFault_OnlyTheRoot: with a usable root, no refusal of a path is a
// root fault: outside, missing inside, linked out, unreadable inside, or of
// the wrong shape.
func TestRootFault_OnlyTheRoot(t *testing.T) {
	tr := newConfineTree(t)
	escape := confineSymlink(t, tr.outside, filepath.Join(tr.root, "escape"))
	paths := []string{tr.outside, filepath.Join(tr.root, "missing"), escape, "relative", tr.root + "/a/../b"}
	if inner := confineLockedChild(t, tr.root); inner != "" {
		paths = append(paths, inner)
	}
	p := NewLocalSources(tr.root, false, false)
	for _, path := range paths {
		wantNoRootFault(t, p, path)
	}
}

// wantNoRootFault fails if ingest, browse or dispatch under p's usable root
// reports its refusal of path as a root fault.
func wantNoRootFault(t *testing.T, p LocalSources, path string) {
	t.Helper()
	_, ensureErr := EnsureWithinRoot(p.Root, path)
	for what, err := range map[string]error{"EnsureWithinRoot": ensureErr, "ResolveDir": p.ResolveDir(path), "Recheck": p.Recheck(path)} {
		if errors.Is(err, ErrRootUnavailable) {
			t.Errorf("%s(%q) = %v; a refusal of the path is not a root fault", what, path, err)
		}
	}
}

// TestLocalSources_CheckRoot: the startup check reports exactly the root
// faults a confined path would meet, and nothing when the policy confines
// nothing (disabled, read-only, or no root).
func TestLocalSources_CheckRoot(t *testing.T) {
	for name, b := range brokenRoots(t) {
		wantErrIs(t, "CheckRoot, "+name, NewLocalSources(b.root, false, false).CheckRoot(), ErrRootUnavailable)
		for _, p := range []LocalSources{{}, NewLocalSources(b.root, false, true)} {
			wantErrIs(t, "CheckRoot of a disabled policy, "+name, p.CheckRoot(), nil)
		}
	}
	tr := newConfineTree(t)
	for _, p := range []LocalSources{
		NewLocalSources(tr.root, false, false),
		NewLocalSources(tr.rootLink, true, false),
		NewLocalSources("", true, false),
	} {
		wantErrIs(t, "CheckRoot("+p.Root+")", p.CheckRoot(), nil)
	}
}
