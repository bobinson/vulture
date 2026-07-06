package staging

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ignoreSet holds the root-level .gitignore/.vultureignore patterns of a
// source dir, split into directory patterns (trailing '/') and plain
// globs. See the package doc for the supported syntax subset.
type ignoreSet struct {
	dirPatterns []string // "fixtures/" → "fixtures"; matched against dirs only
	patterns    []string // globs matched against base name + rel path
}

// loadIgnores reads the ignore files at the source root. Missing files
// simply contribute no patterns. Honors VULTURE_IGNORE_GITIGNORE=true by
// skipping .gitignore (still applying .vultureignore) — matching the
// in-tree scanner's contract (file_scanner._load_ignore_spec), so the
// staged tree a container plugin scans and the tree the skills scan don't
// diverge (0058 review, MEDIUM).
func loadIgnores(srcDir string) *ignoreSet {
	s := &ignoreSet{}
	names := []string{".gitignore", ".vultureignore"}
	if os.Getenv("VULTURE_IGNORE_GITIGNORE") == "true" {
		names = []string{".vultureignore"}
	}
	for _, name := range names {
		s.addFile(filepath.Join(srcDir, name))
	}
	return s
}

func (s *ignoreSet) addFile(p string) {
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		s.addPattern(strings.TrimSpace(line))
	}
}

func (s *ignoreSet) addPattern(line string) {
	if !isSupportedPattern(line) {
		return
	}
	if dir, ok := strings.CutSuffix(line, "/"); ok {
		s.dirPatterns = append(s.dirPatterns, dir)
		return
	}
	s.patterns = append(s.patterns, line)
}

// isSupportedPattern filters the documented subset: blank lines, '#'
// comments, and '!' negation lines (unsupported) are not patterns.
func isSupportedPattern(line string) bool {
	return line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!")
}

// matches reports whether the entry at rel is excluded. Directory
// patterns apply to dirs only; plain globs apply to any entry.
func (s *ignoreSet) matches(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	if isDir && matchAny(s.dirPatterns, rel) {
		return true
	}
	return matchAny(s.patterns, rel)
}

// matchAny globs each pattern against the entry's base name (gitignore's
// slashless-pattern-matches-anywhere rule) and its full rel path.
func matchAny(patterns []string, rel string) bool {
	base := path.Base(rel)
	for _, pat := range patterns {
		if globMatch(pat, base) || globMatch(pat, rel) {
			return true
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
