package localdev

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// buildInputSuffixes are the file types compiled into the backend binary.
// `.sql` is here because the migration runner embeds the whole migrations
// directory with //go:embed — a new migration file changes the binary just as
// surely as a .go file does, and treating it as inert is how a tree can carry
// migration 027 while the running binary still knows only 26.
var buildInputSuffixes = []string{".go", ".sql", ".tmpl", ".json"}

// backendNeedsRebuild reports whether bin must be rebuilt from backendDir.
//
// The previous guard was `os.IsNotExist(bin)`, which rebuilds only the first
// time. Everything after that served whatever binary happened to exist, so a
// source change was invisible at runtime and the supervisor still printed its
// success line — the same failure mode feature 0069 guards against on ports.
func backendNeedsRebuild(bin, backendDir string) bool {
	info, err := os.Stat(bin)
	if err != nil {
		return true
	}
	built := info.ModTime()

	stale := false
	// A walk error is not evidence the tree is unchanged, so fail toward
	// rebuilding: a needless build costs seconds, a skipped one costs a
	// debugging session against code that is not running.
	if walkErr := filepath.WalkDir(backendDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipBuildInputDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isBuildInput(d.Name()) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.ModTime().After(built) {
			stale = true
			return filepath.SkipAll
		}
		return nil
	}); walkErr != nil {
		return true
	}
	return stale
}

func skipBuildInputDir(name string) bool {
	return name == "bin" || name == "testdata" || strings.HasPrefix(name, ".")
}

func isBuildInput(name string) bool {
	for _, s := range buildInputSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}
