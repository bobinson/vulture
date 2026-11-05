// Package scanignore holds the folders Vulture skips by default, so the
// backend skips the folders the scanner skips without a list of its own.
//
// default.vultureignore is a byte-identical copy of the repository root's
// default.vultureignore, the file to edit (a test compares them).
// Each line is a directory-name glob ending in '/', matching a directory of
// that name at any depth. A scanned project brings one back with a negation in
// its root .vultureignore. The version-control stores are the only names in
// code, and nothing brings them back.
package scanignore

import (
	_ "embed"
	"fmt"
	"path"
	"regexp"
	"strings"
)

//go:embed default.vultureignore
var defaultFile string

var defaultGlobs = mustParse(defaultFile)

var vcsDirs = map[string]bool{".git": true, ".svn": true, ".hg": true, ".bzr": true}

// VCS reports whether name is a version-control store, which is never walked
// whatever any ignore file says.
func VCS(name string) bool {
	return vcsDirs[name]
}

// Default reports whether the default ignore file lists a directory called
// name.
func Default(name string) bool {
	for _, glob := range defaultGlobs {
		if ok, err := path.Match(glob, name); err == nil && ok {
			return true
		}
	}
	return false
}

// DefaultGlobs returns the default ignore file's directory-name globs, without
// their trailing '/'.
func DefaultGlobs() []string {
	return append([]string(nil), defaultGlobs...)
}

func mustParse(text string) []string {
	globs, err := parseGlobs(text)
	if err != nil {
		panic(err)
	}
	return globs
}

// parseGlobs reads the file's directory-name globs; anything else is refused,
// because the scanner and the opengrep plugin read each line as a bare name.
func parseGlobs(text string) ([]string, error) {
	var globs []string
	for _, line := range patternLines(text) {
		glob, err := directoryGlob(line)
		if err != nil {
			return nil, err
		}
		globs = append(globs, glob)
	}
	return globs, nil
}

// patternLines drops blank lines and '#' comments.
func patternLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// globLine is one directory-name glob and its trailing '/': no negation, no
// escape, no '/' inside the name.
var globLine = regexp.MustCompile(`^([^!\\/][^/]*)/$`)

func directoryGlob(line string) (string, error) {
	m := globLine.FindStringSubmatch(line)
	if m == nil {
		return "", fmt.Errorf("scanignore: not a directory-name glob: %q", line)
	}
	if _, err := path.Match(m[1], ""); err != nil {
		return "", fmt.Errorf("scanignore: bad glob %q: %w", line, err)
	}
	return m[1], nil
}
