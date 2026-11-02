package staging

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ignoreSet holds the patterns of one directory's ignore files, split into
// directory patterns (trailing '/') and plain globs, matched against paths
// relative to that directory. See the package doc for the supported syntax
// subset.
type ignoreSet struct {
	dirPatterns []string // "fixtures/" → "fixtures"; matched against dirs only
	patterns    []string // globs matched against base name + rel path
}

// ignoreTree is the ignore sets in force during one staging walk: the
// root's .gitignore and .vultureignore, and the .gitignore of every
// directory the walk enters, keyed by root-relative slash path ("" for the
// root). Each applies to the entries beneath its own directory. The subset
// has no negation, so an entry is excluded when any of them matches.
type ignoreTree struct {
	readGitignore bool
	byDir         map[string]*ignoreSet
}

// loadIgnores reads the ignore files at the source root. Missing files
// simply contribute no patterns. Honors VULTURE_IGNORE_GITIGNORE=true by
// skipping every .gitignore (still applying .vultureignore) — matching the
// in-tree scanner's contract (file_scanner._load_ignore_spec), so the
// staged tree a container plugin scans and the tree the skills scan don't
// diverge (0058 review, MEDIUM).
func loadIgnores(srcDir string) *ignoreTree {
	t := &ignoreTree{
		readGitignore: os.Getenv("VULTURE_IGNORE_GITIGNORE") != "true",
		byDir:         map[string]*ignoreSet{},
	}
	t.enter(srcDir, "")
	root := t.setFor("")
	root.addFile(filepath.Join(srcDir, ".vultureignore"))
	return t
}

// enter reads the .gitignore of the directory dir (root-relative rel) as
// the walk descends into it. A directory the walk skips is never entered,
// so a .gitignore inside an ignored directory is never read, as in git.
func (t *ignoreTree) enter(dir, rel string) {
	if t.readGitignore {
		t.setFor(rel).addFile(filepath.Join(dir, ".gitignore"))
	}
}

func (t *ignoreTree) setFor(rel string) *ignoreSet {
	key := filepath.ToSlash(rel)
	if t.byDir[key] == nil {
		t.byDir[key] = &ignoreSet{}
	}
	return t.byDir[key]
}

// matches reports whether the entry at rel is excluded by the ignore set
// of any directory above it, each tested with rel made relative to it.
func (t *ignoreTree) matches(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	for _, dir := range ancestors(rel) {
		if s := t.byDir[dir]; s != nil && s.matches(strings.TrimPrefix(rel, dir+"/"), isDir) {
			return true
		}
	}
	return false
}

// ancestors lists the root-relative directories above rel, nearest first,
// ending with the root ("").
func ancestors(rel string) []string {
	var dirs []string
	for dir := path.Dir(rel); dir != "."; dir = path.Dir(dir) {
		dirs = append(dirs, dir)
	}
	return append(dirs, "")
}

func (s *ignoreSet) addFile(p string) {
	data, ok := readRegular(p)
	if !ok {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		s.addPattern(strings.TrimSpace(line))
	}
}

// readRegular reads one ignore file, unless it is missing or not a regular
// file: git does not follow a symlinked .gitignore, and following one would
// read rules from outside the source tree.
func readRegular(p string) ([]byte, bool) {
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	data, err := os.ReadFile(p)
	return data, err == nil
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
