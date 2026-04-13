// Package iniutil provides a minimal INI file parser shared across
// the backend and CLI modules.
package iniutil

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// FindINIPath locates config.ini by searching:
//  1. VULTURE_CONFIG env var
//  2. Walk up from the executable directory
//  3. Walk up from the current working directory
//
// Returns "" if not found.
func FindINIPath() string {
	if v := os.Getenv("VULTURE_CONFIG"); v != "" {
		return v
	}
	if self, err := os.Executable(); err == nil {
		if p := WalkUpFor(filepath.Dir(self), "config.ini"); p != "" {
			return p
		}
	}
	cwd, _ := os.Getwd()
	if p := WalkUpFor(cwd, "config.ini"); p != "" {
		return p
	}
	return ""
}

// WalkUpFor searches up to 5 parent directories for a file with the given name.
func WalkUpFor(dir, name string) string {
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// ParseINI parses a minimal INI file into a flat "section.key" -> value map.
// Lines starting with # or ; are comments. Section headers are [section].
// Returns an empty map (not an error) if the file does not exist.
func ParseINI(path string) map[string]string {
	vals := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return vals
	}
	defer f.Close()

	var section string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[section+"."+strings.TrimSpace(strings.ToLower(k))] = strings.TrimSpace(v)
	}
	return vals
}
