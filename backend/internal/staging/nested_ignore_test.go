package staging

import (
	"os"
	"path/filepath"
	"testing"
)

// A .gitignore below the source root applies to the entries beneath its own
// directory, with its patterns relative to that directory, as git and the
// in-tree scanner apply it. Without this the staged tree a container plugin
// scans holds what the skills never read: a package's ignored output, or a
// cache directory that ignores itself (Hypothesis writes `*` into
// .hypothesis/.gitignore).

func assertStaged(t *testing.T, staged string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if _, err := os.Lstat(filepath.Join(staged, rel)); err != nil {
			t.Errorf("%s should be staged: %v", rel, err)
		}
	}
}

func assertNotStaged(t *testing.T, staged string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if _, err := os.Lstat(filepath.Join(staged, rel)); !os.IsNotExist(err) {
			t.Errorf("%s must not be staged (lstat err=%v)", rel, err)
		}
	}
}

func TestStage_HonorsNestedGitignore(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "pkg/.gitignore", "stash/\n*.tmp\n")
	writeFile(t, src, "pkg/stash/a.py", "x = 1\n")
	writeFile(t, src, "pkg/deep/stash/b.py", "x = 1\n")
	writeFile(t, src, "pkg/scratch.tmp", "noise")
	writeFile(t, src, "pkg/app.py", "x = 1\n")
	writeFile(t, src, "stash/c.py", "x = 1\n")
	writeFile(t, src, "root.tmp", "kept")

	staged := mustStage(t, src, t.TempDir(), "audit-nested")

	assertNotStaged(t, staged, "pkg/stash/a.py", "pkg/deep/stash/b.py", "pkg/scratch.tmp")
	assertStaged(t, staged, "pkg/app.py", "stash/c.py", "root.tmp")
}

func TestStage_NestedPathPatternIsRelativeToItsDirectory(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "pkg/.gitignore", "gen/out.py\n")
	writeFile(t, src, "pkg/gen/out.py", "x = 1\n")
	writeFile(t, src, "gen/out.py", "x = 1\n")

	staged := mustStage(t, src, t.TempDir(), "audit-nested-rel")

	assertNotStaged(t, staged, "pkg/gen/out.py")
	assertStaged(t, staged, "gen/out.py")
}

func TestStage_SelfIgnoringCacheDirectoryStagesNothing(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, ".hypothesis/.gitignore", "# created by Hypothesis\n*\n")
	writeFile(t, src, ".hypothesis/constants/0a1b2c", "[1, 2]\n")
	writeFile(t, src, "app.py", "x = 1\n")

	staged := mustStage(t, src, t.TempDir(), "audit-selfignore")

	assertNotStaged(t, staged, ".hypothesis/constants", ".hypothesis/.gitignore")
	assertStaged(t, staged, "app.py")
}

func TestStage_IgnoreGitignoreFlagDisablesNestedGitignores(t *testing.T) {
	t.Setenv("VULTURE_IGNORE_GITIGNORE", "true")
	src := t.TempDir()
	writeFile(t, src, "pkg/.gitignore", "stash/\n")
	writeFile(t, src, "pkg/stash/a.py", "x = 1\n")

	staged := mustStage(t, src, t.TempDir(), "audit-nested-flag")

	assertStaged(t, staged, "pkg/stash/a.py")
}

func TestStage_SymlinkedVultureignoreIsNotFollowed(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "rules", "*.py\n")
	writeFile(t, src, "a.py", "x = 1\n")
	if err := os.Symlink(filepath.Join(outside, "rules"), filepath.Join(src, ".vultureignore")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	staged := mustStage(t, src, t.TempDir(), "audit-vi-symlink")

	assertStaged(t, staged, "a.py")
}

func TestStage_SymlinkedNestedGitignoreIsNotFollowed(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "rules", "*.py\n")
	writeFile(t, src, "pkg/a.py", "x = 1\n")
	if err := os.Symlink(filepath.Join(outside, "rules"), filepath.Join(src, "pkg", ".gitignore")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	staged := mustStage(t, src, t.TempDir(), "audit-nested-symlink")

	assertStaged(t, staged, "pkg/a.py")
}
