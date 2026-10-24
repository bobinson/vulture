package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// homeTree builds <tmp>/home/someone with the given entries in it, points
// userHomeDir at it, and returns the home directory.
func homeTree(t *testing.T, entries ...string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home", "someone")
	mkdirs(t, home)
	for _, e := range entries {
		touch(t, filepath.Join(home, e))
	}
	withHome(t, func() (string, error) { return home, nil })
	return home
}

func withHome(t *testing.T, fn func() (string, error)) {
	t.Helper()
	prev := userHomeDir
	userHomeDir = fn
	t.Cleanup(func() { userHomeDir = prev })
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
}

func touch(t *testing.T, p string) {
	t.Helper()
	mkdirs(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func localSource(p string) *model.Source {
	return &model.Source{Type: model.SourceTypeLocal, Path: p}
}

func assertIdentity(t *testing.T, got TargetIdentity, key, root, offset string) {
	t.Helper()
	if got.Key != key || got.Root != root || got.Offset != offset {
		t.Fatalf("identity = {%q %q %q}, want {%q %q %q}", got.Key, got.Root, got.Offset, key, root, offset)
	}
}

func TestResolveTargetStopsBelowHomeMarker(t *testing.T) {
	home := homeTree(t, "package.json")
	scan := filepath.Join(home, "src", "proj")
	touch(t, filepath.Join(scan, "backend", "package.json")) // markers only BELOW the root
	assertIdentity(t, ResolveTarget(localSource(scan)), targetKindPath+scan, scan, "")
}

func TestResolveTargetStopsBelowMarkerAboveHome(t *testing.T) {
	home := homeTree(t)
	touch(t, filepath.Join(filepath.Dir(home), "package.json"))
	scan := filepath.Join(home, "src", "proj")
	mkdirs(t, scan)
	assertIdentity(t, ResolveTarget(localSource(scan)), targetKindPath+scan, scan, "")
}

func TestResolveTargetFindsMarkerBetweenRootAndHome(t *testing.T) {
	home := homeTree(t, "package.json")
	proj := filepath.Join(home, "src", "proj")
	touch(t, filepath.Join(proj, "go.mod"))
	scan := filepath.Join(proj, "backend")
	mkdirs(t, scan)
	assertIdentity(t, ResolveTarget(localSource(scan)), targetKindMarker+hashedRoot(proj), proj, "backend")
}

func TestResolveTargetHomeItselfIsUnchanged(t *testing.T) {
	home := homeTree(t, "package.json")
	assertIdentity(t, ResolveTarget(localSource(home)), targetKindMarker+hashedRoot(home), home, "")
}

func TestResolveTargetUnresolvableHomeIsUnchanged(t *testing.T) {
	home := homeTree(t, "package.json")
	withHome(t, func() (string, error) { return "", errors.New("no home") })
	scan := filepath.Join(home, "src", "proj")
	mkdirs(t, scan)
	assertIdentity(t, ResolveTarget(localSource(scan)), targetKindMarker+hashedRoot(home), home, "src/proj")
}

func TestResolveTargetIgnoresHomeGitCheckout(t *testing.T) {
	home := homeTree(t)
	mkdirs(t, filepath.Join(home, ".git"))
	scan := filepath.Join(home, "src", "proj")
	mkdirs(t, scan)
	assertIdentity(t, ResolveTarget(localSource(scan)), targetKindPath+scan, scan, "")

	// The remote git reports from inside a dotfiles checkout is the HOME
	// repository's, not the project's.
	src := localSource(scan)
	src.GitRemoteURL = "git@github.com:someone/dotfiles.git"
	assertIdentity(t, ResolveTarget(src), targetKindPath+scan, scan, "")
}

func TestResolveTargetKeepsProjectCheckoutBelowHomeGit(t *testing.T) {
	home := homeTree(t)
	mkdirs(t, filepath.Join(home, ".git"))
	proj := filepath.Join(home, "src", "proj")
	mkdirs(t, filepath.Join(proj, ".git"), filepath.Join(proj, "api"))
	src := localSource(filepath.Join(proj, "api"))
	src.GitRemoteURL = "https://github.com/acme/proj.git"
	assertIdentity(t, ResolveTarget(src), targetKindGit+"github.com/acme/proj", proj, "api")
}

func TestRetiredHomeTarget(t *testing.T) {
	home := homeTree(t, "package.json")
	scan := filepath.Join(home, "src", "proj")
	mkdirs(t, scan)
	src := localSource(scan)
	old, ok := retiredHomeTarget(src, ResolveTarget(src))
	if !ok {
		t.Fatal("a scan root below a home marker must report the key the pre-boundary climb gave it")
	}
	assertIdentity(t, old, targetKindMarker+hashedRoot(home), home, "src/proj")

	if _, ok := retiredHomeTarget(localSource(home), ResolveTarget(localSource(home))); ok {
		t.Fatal("scanning $HOME itself retires nothing")
	}
	marked := filepath.Join(home, "src", "marked")
	touch(t, filepath.Join(marked, "go.mod"))
	if _, ok := retiredHomeTarget(localSource(marked), ResolveTarget(localSource(marked))); ok {
		t.Fatal("a root with its own marker resolved identically before the boundary; nothing to retire")
	}
	if _, ok := retiredHomeTarget(nil, TargetIdentity{}); ok {
		t.Fatal("nil source retires nothing")
	}
}

func TestRebaseRetiredPath(t *testing.T) {
	retired := TargetIdentity{Key: "marker:h", Root: "/h", Offset: "src/proj"}
	target := TargetIdentity{Key: "path:/h/src/proj", Root: "/h/src/proj"}
	rebase := rebaseRetired(retired, target)
	for in, want := range map[string]string{
		"src/proj/backend/x.go": "backend/x.go",
		"/abs/file.go":          "/abs/file.go",
		"elsewhere/a.go":        "elsewhere/a.go",
		"src/proj":              "src/proj",
	} {
		if got := rebase(in); got != want {
			t.Errorf("rebase(%q) = %q, want %q", in, got, want)
		}
	}
}
