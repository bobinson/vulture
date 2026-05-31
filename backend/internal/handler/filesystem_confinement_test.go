package handler

import (
	"os"
	"path/filepath"
	"testing"
)

// 0036 Phase 3 — filesystem-browse confinement.
//
// The pre-Phase-3 handler denied a hard-coded denylist (/etc, /root,
// /proc, …) but otherwise let an authenticated user browse anywhere
// the backend process could read. In Mode B that's a directory-
// disclosure surface across the deployment host. These tests pin the
// new contract:
//
//   * Literal ".." path segments rejected at URL parse time.
//   * When VULTURE_SOURCE_ROOT is set, paths outside that root reject
//     with 403; the existing system denylist still applies regardless.
//   * Symlinks pointing outside the source root reject with 403.
//   * Result listings are capped at maxBrowseEntries to prevent
//     pathological responses on huge directories.

func TestRejectsDotDotPath(t *testing.T) {
	bad := []string{
		"..",
		"/foo/..",
		"/foo/../bar",
		"foo/../bar",
		"foo/..",
		"./..",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			_, code, msg := validateBrowsePathWithRoot(p, "")
			if code != 400 {
				t.Errorf("validateBrowsePathWithRoot(%q, %q) code=%d msg=%q; want 400",
					p, "", code, msg)
			}
		})
	}
}

func TestEnforcesSourceRootWhenSet(t *testing.T) {
	tmp := t.TempDir()
	inside := filepath.Join(tmp, "ok")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}

	_, code, _ := validateBrowsePathWithRoot(inside, tmp)
	if code != 0 {
		t.Errorf("inside-root path rejected: code=%d", code)
	}

	outside := t.TempDir()
	_, code, _ = validateBrowsePathWithRoot(outside, tmp)
	if code != 403 {
		t.Errorf("outside-root path code=%d; want 403", code)
	}
}

func TestEmptySourceRootRetainsLegacyBehavior(t *testing.T) {
	// When SourceRoot is unset, the handler falls back to its previous
	// behaviour: the system denylist is the only protection.
	// /etc must still be blocked; /tmp must still be allowed (the
	// scratch directory for dev laptops).
	_, code, _ := validateBrowsePathWithRoot("/etc", "")
	if code != 403 {
		t.Errorf("/etc with empty SourceRoot: code=%d; want 403 (denylist)", code)
	}
	// /tmp may or may not exist on the test host; expect either 0 (ok)
	// or 404 (not found) — but NOT 403.
	_, code, _ = validateBrowsePathWithRoot("/tmp", "")
	if code == 403 {
		t.Errorf("/tmp with empty SourceRoot was forbidden; should be allowed")
	}
}

func TestSymlinkOutsideSourceRootRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(filepath.Join(outside, "target"), link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	_, code, _ := validateBrowsePathWithRoot(link, root)
	if code != 403 {
		t.Errorf("symlink escape: code=%d; want 403", code)
	}
}

// Cap is exercised via buildDirEntries directly so we don't need
// to mock filesystem entries up to maxBrowseEntries+1.
func TestBuildDirEntriesCapsResultSize(t *testing.T) {
	tmp := t.TempDir()
	// Create maxBrowseEntries + 50 visible files.
	want := maxBrowseEntries
	for i := 0; i < want+50; i++ {
		name := filepath.Join(tmp, "f"+ pad4(i) + ".txt")
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	got := buildDirEntries(tmp, entries)
	if len(got) > want {
		t.Errorf("buildDirEntries returned %d entries; cap=%d", len(got), want)
	}
}

func pad4(n int) string {
	s := "0000"
	d := []byte{'0', '0', '0', '0'}
	i := 3
	for n > 0 && i >= 0 {
		d[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	_ = s
	return string(d)
}
