package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// Feature 0091 §7.1. The remote normaliser is the only part of target identity
// that is pure string work, and it is the part that decides whether one
// repository is one target: the day someone switches a checkout from https to
// ssh, every finding in it either keeps its VLT ref or acquires a new one.
func TestNormalizeGitRemote(t *testing.T) {
	const want = "github.com/acme/proj"
	for _, tc := range []struct {
		name, remote, want string
	}{
		{"https with .git", "https://github.com/acme/proj.git", want},
		{"https without .git", "https://github.com/acme/proj", want},
		{"https trailing slash", "https://github.com/acme/proj/", want},
		{"http", "http://github.com/acme/proj.git", want},
		{"git protocol", "git://github.com/acme/proj.git", want},
		{"scp-like ssh", "git@github.com:acme/proj.git", want},
		{"ssh url", "ssh://git@github.com/acme/proj.git", want},
		{"ssh url with port", "ssh://git@github.com:2222/acme/proj.git", want},
		{"https with credentials", "https://user:token@github.com/acme/proj.git", want},
		{"upper-case host", "HTTPS://GitHub.COM/acme/proj.git", want},
		{"surrounding space", "  https://github.com/acme/proj.git\n", want},
		{"nested group", "git@gitlab.com:grp/sub/proj.git", "gitlab.com/grp/sub/proj"},
		{"host only", "https://github.com", "github.com"},
		{"local path remote", "/srv/git/proj.git", "/srv/git/proj"},
		{"empty", "", ""},
		{"blank", "   ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeGitRemote(tc.remote); got != tc.want {
				t.Fatalf("NormalizeGitRemote(%q) = %q, want %q", tc.remote, got, tc.want)
			}
		})
	}
}

// TestNormalizeGitRemoteDistinguishesRepositories is the other half of the
// contract: over-merging is worse than not merging, because it pools one
// project's findings into another's history.
func TestNormalizeGitRemoteDistinguishesRepositories(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://github.com/acme/proj.git", "https://github.com/acme/other.git"},
		{"https://github.com/acme/proj.git", "https://gitlab.com/acme/proj.git"},
		{"https://github.com/acme/proj.git", "https://github.com/other/proj.git"},
		{"git@github.com:acme/Proj.git", "git@github.com:acme/proj.git"},
	} {
		a, b := NormalizeGitRemote(pair[0]), NormalizeGitRemote(pair[1])
		if a == b {
			t.Errorf("%q and %q are different repositories but normalised alike (%q)", pair[0], pair[1], a)
		}
	}
}

// TestResolveTargetGitRemoteBeatsPath is S16 in miniature: the mount is not
// part of the identity when a remote exists.
func TestResolveTargetGitRemoteBeatsPath(t *testing.T) {
	native := ResolveTarget(&model.Source{
		Type: model.SourceTypeGit, Path: "/home/x/proj",
		GitRemoteURL: "https://github.com/acme/proj.git",
	})
	docker := ResolveTarget(&model.Source{
		Type: model.SourceTypeGit, Path: "/mnt/source/proj",
		GitRemoteURL: "git@github.com:acme/proj.git",
	})
	if native.Key != docker.Key {
		t.Fatalf("one repository under two mounts must be one target: %q vs %q", native.Key, docker.Key)
	}
	if native.Key != "git:github.com/acme/proj" {
		t.Fatalf("unexpected key %q", native.Key)
	}
	if native.Offset != "" || docker.Offset != "" {
		t.Fatalf("a scan of the checkout root has no offset: %q / %q", native.Offset, docker.Offset)
	}
}

// TestResolveTargetMarkerAndSubPath pins §7.1 step 2 and §7.2 together: the
// identity of a sub-path scan is the identity of an ancestor, and the offset
// it computes is what the scope check is later built from.
func TestResolveTargetMarkerAndSubPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}

	atRoot := ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: root})
	atSub := ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: sub})

	if atRoot.Key != atSub.Key {
		t.Fatalf("a sub-path scan inherits its root's key: %q vs %q", atRoot.Key, atSub.Key)
	}
	if atRoot.Offset != "" {
		t.Fatalf("root scan offset = %q, want empty", atRoot.Offset)
	}
	if atSub.Offset != "a/b" {
		t.Fatalf("sub-path scan offset = %q, want %q", atSub.Offset, "a/b")
	}
	if !atRoot.Resolved() {
		t.Fatalf("a marker-resolved target is resolved: %q", atRoot.Key)
	}
}

// TestResolveTargetBareMountIsUnattributed pins §7.1 step 3. `/mnt/source` is
// the container mount point itself: the path names no project, and folding it
// into one by guessing is how a project's history acquires another's findings.
func TestResolveTargetBareMountIsUnattributed(t *testing.T) {
	got := ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: "/mnt/source"})
	if got.Key != "unresolved:/mnt/source" {
		t.Fatalf("target key = %q, want %q", got.Key, "unresolved:/mnt/source")
	}
	if got.Resolved() {
		t.Fatal("an unattributed scan must not report itself as resolved")
	}
}

// TestResolveTargetFallsBackToPath covers the third branch: no remote, no
// marker anywhere above. The key must still be non-empty — a row with no
// target key is invisible to every aggregate that replaces the path partition.
func TestResolveTargetFallsBackToPath(t *testing.T) {
	dir := t.TempDir()
	got := ResolveTarget(&model.Source{Type: model.SourceTypeLocal, Path: dir})
	if got.Key == "" {
		t.Fatal("every scanned path must resolve to some target key")
	}
	if got.Key != "path:"+filepath.ToSlash(dir) {
		t.Fatalf("target key = %q, want %q", got.Key, "path:"+filepath.ToSlash(dir))
	}
}

// TestResolveTargetNilSource keeps the resolver total: the closure pass calls
// it on whatever source the caller had, and a nil one must not panic.
func TestResolveTargetNilSource(t *testing.T) {
	if got := ResolveTarget(nil); got.Key != "" || got.Resolved() {
		t.Fatalf("nil source resolved to %+v", got)
	}
}
