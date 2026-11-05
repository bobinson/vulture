package staging

import "testing"

// The staged copy a container plugin scans skips the folders the scanner
// skips: the version-control stores, and every folder of the default ignore
// file (pkg/scanignore) unless the root .vultureignore brings it back with a
// negation. A .gitignore cannot bring one back, as in the scanner.

func TestStage_SkipsTheDefaultIgnoreFilesFolders(t *testing.T) {
	src := t.TempDir()
	for _, rel := range []string{
		"app.py", "data/repo.py", "fixtures/case.py", "src-backup/old.py",
		".claude/settings.json", "pkg/build/out.js", ".hg/store",
	} {
		writeFile(t, src, rel, "x")
	}
	staged := mustStage(t, src, t.TempDir(), "audit-defaults")
	assertStaged(t, staged, "app.py", "data/repo.py")
	assertNotStaged(t, staged, "fixtures", "src-backup", ".claude", "pkg/build", ".hg")
}

func TestStage_RootVultureignoreBringsADefaultFolderBack(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, ".vultureignore", "!build/\n!.git/\n")
	writeFile(t, src, ".gitignore", "!dist/\n")
	for _, rel := range []string{"build/a.js", "web/build/b.js", "dist/c.js", ".git/config"} {
		writeFile(t, src, rel, "x")
	}
	staged := mustStage(t, src, t.TempDir(), "audit-back")
	assertStaged(t, staged, "build/a.js", "web/build/b.js")
	assertNotStaged(t, staged, "dist", ".git")
}

func TestStage_APathNegationBringsBackThatFolderOnly(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, ".vultureignore", "!web/build/\n")
	writeFile(t, src, "build/a.js", "x")
	writeFile(t, src, "web/build/b.js", "x")
	staged := mustStage(t, src, t.TempDir(), "audit-path")
	assertStaged(t, staged, "web/build/b.js")
	assertNotStaged(t, staged, "build")
}

// A negation re-includes what an earlier line of its file excluded, and the
// root .vultureignore overrides every .gitignore, as git and the scanner
// apply them.
func TestStage_HonorsNegation(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, ".gitignore", "*.log\n!keep.log\ngenerated/\n")
	writeFile(t, src, ".vultureignore", "!generated/\n")
	for _, rel := range []string{"drop.log", "keep.log", "generated/api.go"} {
		writeFile(t, src, rel, "x")
	}
	staged := mustStage(t, src, t.TempDir(), "audit-neg")
	assertStaged(t, staged, "keep.log", "generated/api.go")
	assertNotStaged(t, staged, "drop.log")
}
