package staging

// RED tests for feature 0058 Phase 0 (S3 / R11, LLD section 4a, work
// items P0b/P0c/P0d, test T12). This package does not exist yet — the
// compile failure on the undefined symbols below is the expected RED
// state. The GREEN team must implement, in this package, EXACTLY:
//
//   func Stage(ctx context.Context, srcDir, auditsDir, auditID string) (stagedPath string, err error)
//     - copies the srcDir tree into <auditsDir>/<auditID>/ and returns
//       that path;
//     - SKIPS the dirs: node_modules, .git, vendor, .venv, venv,
//       __pycache__, target, dist, build, out;
//     - honors .gitignore and .vultureignore patterns found at the
//       srcDir root, when present;
//     - preserves symlinks AS SYMLINKS (never dereferences/follows).
//   func Reap(auditsDir, auditID string) error
//     - removes <auditsDir>/<auditID>; a missing dir is NOT an error.
//   func Sweep(auditsDir string, isActive func(auditID string) bool) error
//     - removes every entry of auditsDir whose isActive(name) is false.
//   func StagedContainerPath(auditID string) string
//     - returns path.Join("/audit-inputs", auditID).
//   func HasCapacity(srcBytes, freeBytes int64, margin float64) bool
//     - pure predicate: free >= src*margin.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates a file (and parent dirs) under root with content.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func mustStage(t *testing.T, srcDir, auditsDir, auditID string) string {
	t.Helper()
	staged, err := Stage(context.Background(), srcDir, auditsDir, auditID)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	return staged
}

func TestStage_CopiesTreeIntoAuditsDirSlashAuditID(t *testing.T) {
	src := t.TempDir()
	audits := t.TempDir()
	writeFile(t, src, "main.go", "package main\n")
	writeFile(t, src, "sub/dir/file.txt", "hello staging\n")

	staged := mustStage(t, src, audits, "audit-123")

	want := filepath.Join(audits, "audit-123")
	if staged != want {
		t.Errorf("Stage returned %q; want <auditsDir>/<auditID> = %q", staged, want)
	}
	got, err := os.ReadFile(filepath.Join(staged, "main.go"))
	if err != nil {
		t.Fatalf("staged main.go missing: %v", err)
	}
	if string(got) != "package main\n" {
		t.Errorf("staged main.go content = %q; want %q", got, "package main\n")
	}
	got, err = os.ReadFile(filepath.Join(staged, "sub", "dir", "file.txt"))
	if err != nil {
		t.Fatalf("staged nested file missing: %v", err)
	}
	if string(got) != "hello staging\n" {
		t.Errorf("staged nested content = %q; want %q", got, "hello staging\n")
	}
}

func TestStage_SkipsVendoredAndBuildDirs(t *testing.T) {
	src := t.TempDir()
	audits := t.TempDir()
	writeFile(t, src, "keep.txt", "keep")
	skipDirs := []string{
		"node_modules", ".git", "vendor", ".venv", "venv",
		"__pycache__", "target", "dist", "build", "out",
	}
	for _, d := range skipDirs {
		writeFile(t, src, filepath.Join(d, "junk.bin"), "junk")
	}

	staged := mustStage(t, src, audits, "audit-skip")

	if _, err := os.Stat(filepath.Join(staged, "keep.txt")); err != nil {
		t.Fatalf("keep.txt should be staged: %v", err)
	}
	for _, d := range skipDirs {
		if _, err := os.Lstat(filepath.Join(staged, d)); !os.IsNotExist(err) {
			t.Errorf("skip dir %q must NOT be staged (lstat err=%v)", d, err)
		}
	}
}

func TestStage_HonorsVultureignore(t *testing.T) {
	src := t.TempDir()
	audits := t.TempDir()
	writeFile(t, src, ".vultureignore", "fixtures/\n*.recorded\n")
	writeFile(t, src, "code.py", "print('hi')\n")
	writeFile(t, src, "fixtures/big_corpus.json", "{}")
	writeFile(t, src, "session.recorded", "bytes")

	staged := mustStage(t, src, audits, "audit-vign")

	if _, err := os.Stat(filepath.Join(staged, "code.py")); err != nil {
		t.Fatalf("code.py should be staged: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(staged, "fixtures", "big_corpus.json")); !os.IsNotExist(err) {
		t.Errorf(".vultureignore dir pattern fixtures/ must be excluded (lstat err=%v)", err)
	}
	if _, err := os.Lstat(filepath.Join(staged, "session.recorded")); !os.IsNotExist(err) {
		t.Errorf(".vultureignore glob *.recorded must be excluded (lstat err=%v)", err)
	}
}

func TestStage_HonorsGitignore(t *testing.T) {
	src := t.TempDir()
	audits := t.TempDir()
	writeFile(t, src, ".gitignore", "*.log\n")
	writeFile(t, src, "app.go", "package app\n")
	writeFile(t, src, "debug.log", "noise")

	staged := mustStage(t, src, audits, "audit-gign")

	if _, err := os.Stat(filepath.Join(staged, "app.go")); err != nil {
		t.Fatalf("app.go should be staged: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(staged, "debug.log")); !os.IsNotExist(err) {
		t.Errorf(".gitignore pattern *.log must be excluded (lstat err=%v)", err)
	}
}

func TestStage_PreservesSymlinksNeverDereferences(t *testing.T) {
	// S3 core case: a repo symlink to a host file (e.g. /etc/hostname)
	// must be copied AS A SYMLINK, so host bytes are never dragged into
	// the staging dir.
	src := t.TempDir()
	audits := t.TempDir()
	writeFile(t, src, "readme.md", "docs")
	if err := os.Symlink("/etc/hostname", filepath.Join(src, "sneaky")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	staged := mustStage(t, src, audits, "audit-sym")

	info, err := os.Lstat(filepath.Join(staged, "sneaky"))
	if err != nil {
		t.Fatalf("staged symlink entry missing: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("staged 'sneaky' must be a symlink, got mode %v (host file was dereferenced/copied)", info.Mode())
	}
	target, err := os.Readlink(filepath.Join(staged, "sneaky"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "/etc/hostname" {
		t.Errorf("symlink target = %q; want /etc/hostname (preserved as-is)", target)
	}
}

func TestReap_RemovesStagedDirAndIsIdempotent(t *testing.T) {
	src := t.TempDir()
	audits := t.TempDir()
	writeFile(t, src, "f.txt", "x")
	staged := mustStage(t, src, audits, "audit-reap")

	if err := Reap(audits, "audit-reap"); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Errorf("staged dir must be removed after Reap (lstat err=%v)", err)
	}
	// Missing dir is not an error (idempotent).
	if err := Reap(audits, "audit-reap"); err != nil {
		t.Errorf("Reap on already-removed dir must be nil, got %v", err)
	}
	if err := Reap(audits, "never-existed"); err != nil {
		t.Errorf("Reap on never-existed dir must be nil, got %v", err)
	}
}

func TestSweep_KeepsActiveRemovesOrphans(t *testing.T) {
	audits := t.TempDir()
	writeFile(t, audits, "active-1/a.txt", "a")
	writeFile(t, audits, "orphan-1/b.txt", "b")
	writeFile(t, audits, "orphan-2/c.txt", "c")

	err := Sweep(audits, func(auditID string) bool { return auditID == "active-1" })
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, err := os.Stat(filepath.Join(audits, "active-1", "a.txt")); err != nil {
		t.Errorf("active staged dir must survive Sweep: %v", err)
	}
	for _, orphan := range []string{"orphan-1", "orphan-2"} {
		if _, err := os.Lstat(filepath.Join(audits, orphan)); !os.IsNotExist(err) {
			t.Errorf("orphan %q must be removed by Sweep (lstat err=%v)", orphan, err)
		}
	}
}

func TestStagedContainerPath_JoinsUnderAuditInputs(t *testing.T) {
	if got := StagedContainerPath("audit-123"); got != "/audit-inputs/audit-123" {
		t.Errorf("StagedContainerPath(audit-123) = %q; want /audit-inputs/audit-123", got)
	}
}

func TestHasCapacity_Boundaries(t *testing.T) {
	cases := []struct {
		name   string
		src    int64
		free   int64
		margin float64
		want   bool
	}{
		{"exact-equal-allowed", 100, 150, 1.5, true},
		{"one-byte-short-refused", 100, 149, 1.5, false},
		{"margin-1-exact", 100, 100, 1.0, true},
		{"margin-1-short", 100, 99, 1.0, false},
		{"plenty-free", 10, 1_000_000, 2.0, true},
		{"zero-src-always-fits", 0, 0, 1.5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasCapacity(tc.src, tc.free, tc.margin); got != tc.want {
				t.Errorf("HasCapacity(%d, %d, %v) = %v; want %v", tc.src, tc.free, tc.margin, got, tc.want)
			}
		})
	}
}
