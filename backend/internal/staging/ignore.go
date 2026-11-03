package staging

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ignoreSet holds the pattern lines of one ignore file, in order, matched
// against paths relative to that file's directory. See the package doc for
// the supported syntax subset.
type ignoreSet struct {
	rules []ignoreRule
}

// ignoreRule is one pattern line: its glob, whether it matches directories
// only (a trailing '/'), and whether it re-includes (a leading '!').
type ignoreRule struct {
	glob    string
	dirOnly bool
	negate  bool
}

// ignoreTree is the ignore files in force during one staging walk: the
// root's .vultureignore, and the .gitignore of the root and of every
// directory the walk enters, keyed by root-relative slash path ("" for the
// root). Each .gitignore applies to the entries beneath its own directory.
type ignoreTree struct {
	readGitignore bool
	vultureignore *ignoreSet
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
		vultureignore: &ignoreSet{},
		byDir:         map[string]*ignoreSet{},
	}
	t.vultureignore.addFile(filepath.Join(srcDir, ".vultureignore"))
	t.enter(srcDir, "")
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

// matches reports whether the ignore files exclude the entry at rel, as
// git and the scanner decide it: the .vultureignore when one of its lines
// matches, else the nearest .gitignore above rel with a matching line.
func (t *ignoreTree) matches(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	if excluded, ok := t.vultureignore.verdict(rel, isDir); ok {
		return excluded
	}
	for _, dir := range ancestors(rel) {
		if excluded, ok := t.gitignoreVerdict(dir, rel, isDir); ok {
			return excluded
		}
	}
	return false
}

// gitignoreVerdict is the verdict of the .gitignore of dir, if it has one,
// on the entry at rel.
func (t *ignoreTree) gitignoreVerdict(dir, rel string, isDir bool) (excluded, ok bool) {
	s := t.byDir[dir]
	if s == nil {
		return false, false
	}
	return s.verdict(strings.TrimPrefix(rel, dir+"/"), isDir)
}

// bringsBack reports whether the root .vultureignore re-includes the
// directory at rel, which overrides the default ignore file
// (pkg/scanignore). A .gitignore never does.
func (t *ignoreTree) bringsBack(rel string) bool {
	excluded, ok := t.vultureignore.verdict(filepath.ToSlash(rel), true)
	return ok && !excluded
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
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	var r ignoreRule
	line, r.negate = strings.CutPrefix(line, "!")
	r.glob, r.dirOnly = strings.CutSuffix(line, "/")
	if r.glob != "" {
		s.rules = append(s.rules, r)
	}
}

// verdict reports whether the set excludes the entry at rel: the last line
// matching it decides, and ok is false when no line does.
func (s *ignoreSet) verdict(rel string, isDir bool) (excluded, ok bool) {
	for _, r := range s.rules {
		if r.matches(rel, isDir) {
			excluded, ok = !r.negate, true
		}
	}
	return excluded, ok
}

// matches globs the rule against the entry's base name (gitignore's
// slashless-pattern-matches-anywhere rule) and its full rel path. A
// directory pattern applies to directories only.
func (r ignoreRule) matches(rel string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	return globMatch(r.glob, path.Base(rel)) || globMatch(r.glob, rel)
}

func globMatch(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
