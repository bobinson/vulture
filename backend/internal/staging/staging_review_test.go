package staging

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// #1 (review): staging honors VULTURE_IGNORE_GITIGNORE=true by NOT applying
// .gitignore (still applying .vultureignore), matching the in-tree scanner
// so the two detection tiers scan the same file set.
func TestStage_HonorsIgnoreGitignoreFlag(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, ".gitignore", "secrets.py\n")
	writeFile(t, src, "secrets.py", "TOKEN = 'x'\n")
	writeFile(t, src, "app.py", "print(1)\n")

	t.Setenv("VULTURE_IGNORE_GITIGNORE", "true")
	dst := t.TempDir()
	staged, err := Stage(context.Background(), src, dst, "a1")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staged, "secrets.py")); err != nil {
		t.Errorf("with VULTURE_IGNORE_GITIGNORE=true, .gitignore'd secrets.py must still be staged: %v", err)
	}

	// Sanity: without the flag, the .gitignore pattern IS applied.
	os.Unsetenv("VULTURE_IGNORE_GITIGNORE")
	dst2 := t.TempDir()
	staged2, err := Stage(context.Background(), src, dst2, "a2")
	if err != nil {
		t.Fatalf("Stage (no flag): %v", err)
	}
	if _, err := os.Stat(filepath.Join(staged2, "secrets.py")); !os.IsNotExist(err) {
		t.Errorf("without the flag, secrets.py should be gitignored out; stat err=%v", err)
	}
}

// #2 (review): copyFile opens with O_NOFOLLOW so a path that is (or becomes)
// a symlink is never dereferenced into the staged tree.
func TestCopyFile_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("host-only bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := copyFile(link, dst, fsDirEntry{info}); err == nil {
		t.Errorf("copyFile followed a symlink; expected O_NOFOLLOW error")
	}
}

// #8 (review): Stage honors a pre-canceled context and leaves no partial
// tree behind.
func TestStage_HonorsContextCancellation(t *testing.T) {
	src := t.TempDir()
	for _, n := range []string{"a.py", "b.py", "c.py"} {
		writeFile(t, src, n, "x\n")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before any copy
	dst := t.TempDir()
	_, err := Stage(ctx, src, dst, "cancelled")
	if err == nil {
		t.Fatalf("Stage with a canceled context must return an error")
	}
	if _, statErr := os.Stat(filepath.Join(dst, "cancelled")); !os.IsNotExist(statErr) {
		t.Errorf("canceled Stage must not leave a partial tree; stat err=%v", statErr)
	}
}

// fsDirEntry adapts an os.FileInfo to the fs.DirEntry copyFile needs.
type fsDirEntry struct{ fi os.FileInfo }

func (d fsDirEntry) Name() string               { return d.fi.Name() }
func (d fsDirEntry) IsDir() bool                { return d.fi.IsDir() }
func (d fsDirEntry) Type() os.FileMode          { return d.fi.Mode().Type() }
func (d fsDirEntry) Info() (os.FileInfo, error) { return d.fi, nil }
