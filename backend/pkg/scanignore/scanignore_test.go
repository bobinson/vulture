package scanignore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The repository root's default.vultureignore is the file the folder list is
// edited in; this package embeds a copy, because go:embed cannot reach outside
// the module. A hard failure, never a skip: a copy that quietly stops being
// compared is a second list again.
func TestDefaultFileIsTheRootFile(t *testing.T) {
	// backend/pkg/scanignore -> backend/pkg -> backend -> repo root
	p := filepath.Join("..", "..", "..", "default.vultureignore")
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("the root default ignore file not found at %s: %v", p, err)
	}
	if !bytes.Equal([]byte(defaultFile), want) {
		t.Fatalf("backend/pkg/scanignore/default.vultureignore differs from %s: copy it over", p)
	}
}

func TestDefaultMatchesTheListedFolders(t *testing.T) {
	for _, name := range []string{"node_modules", "build", "fixtures", ".vscode", "src-backup", "lib_old"} {
		if !Default(name) {
			t.Errorf("Default(%q) = false; the file lists it", name)
		}
	}
	for _, name := range []string{"data", "bin", "env", "mocks", "src", "Build", ".git"} {
		if Default(name) {
			t.Errorf("Default(%q) = true; the file does not list it", name)
		}
	}
}

func TestVCSNamesOnlyTheVersionControlStores(t *testing.T) {
	for _, name := range []string{".git", ".svn", ".hg", ".bzr"} {
		if !VCS(name) {
			t.Errorf("VCS(%q) = false", name)
		}
	}
	if VCS("node_modules") {
		t.Error("VCS(node_modules) = true; it is a default, which a project can bring back")
	}
}

func TestEveryLineIsADirectoryNameGlob(t *testing.T) {
	globs := DefaultGlobs()
	if len(globs) == 0 {
		t.Fatal("the default ignore file lists no folder")
	}
	for _, bad := range []string{"build", "!build/", "web/build/", "/build/", "/"} {
		if _, err := parseGlobs(bad + "\n"); err == nil {
			t.Errorf("parseGlobs accepted %q, which is not a directory-name glob", bad)
		}
	}
}
