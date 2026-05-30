package pluginregistry

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// LoadOptions configures plugin discovery.
type LoadOptions struct {
	// LocalDir is the per-user plugin directory, typically
	// ~/.vulture/plugins. Empty disables the local lookup.
	LocalDir string

	// BuiltinDir is the bundled-plugin directory (feature 0053).
	// Manifests discovered here carry Source="builtin" and are the
	// only manifests permitted to combine tier=in-tree with a
	// non-in-tree runtime (e.g. container). Empty disables the
	// builtin lookup. Defaults from VULTURE_BUILTIN_PLUGINS_DIR.
	BuiltinDir string

	// ExtraDirs is a colon-separated list from VULTURE_PLUGIN_DIRS.
	// Each entry is either a directory (scanned recursively for
	// plugin.toml) or a direct file path.
	ExtraDirs []string

	// IncludeVirtual, when true, prepends synthesised manifests
	// for in-tree agents. Defaults to true via DefaultLoadOptions.
	IncludeVirtual bool

	// Logger receives non-fatal warnings (invalid manifest, duplicate
	// name, etc.). Defaults to log.Default().
	Logger *log.Logger
}

// DefaultLoadOptions returns the standard production configuration:
// virtual in-tree agents, ~/.vulture/plugins, env override.
func DefaultLoadOptions() LoadOptions {
	home, _ := os.UserHomeDir()
	var local string
	if home != "" {
		local = filepath.Join(home, ".vulture", "plugins")
	}
	return LoadOptions{
		LocalDir:       local,
		BuiltinDir:     os.Getenv("VULTURE_BUILTIN_PLUGINS_DIR"),
		ExtraDirs:      splitColon(os.Getenv("VULTURE_PLUGIN_DIRS")),
		IncludeVirtual: true,
	}
}

func splitColon(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ":")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Load discovers plugins per the supplied options. The returned slice
// is ordered: in-tree first (preserves AllAgents order), then local,
// then ExtraDirs. Duplicate names from later sources are skipped with
// a logged warning, EXCEPT that ExtraDirs entries are allowed to
// override local entries (useful for tests + packaging overrides).
func Load(opts LoadOptions) []Plugin {
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}

	var plugins []Plugin
	if opts.IncludeVirtual {
		plugins = append(plugins, AllVirtualPlugins()...)
	}

	plugins = appendUnique(plugins, discoverDir(opts.BuiltinDir, "builtin", logger), logger, false)
	plugins = appendUnique(plugins, discoverDir(opts.LocalDir, "local", logger), logger, false)
	for _, dir := range opts.ExtraDirs {
		plugins = appendUnique(plugins, discoverDir(dir, "env:"+dir, logger), logger, true)
	}
	return plugins
}

// appendUnique merges `incoming` into `existing`, dropping any
// already-present name. If allowOverride is true, an incoming plugin
// replaces an existing one with the same name (used for env-dir
// overrides over local installs).
func appendUnique(existing, incoming []Plugin, logger *log.Logger, allowOverride bool) []Plugin {
	idx := indexByName(existing)
	for _, p := range incoming {
		name := p.Name()
		if i, ok := idx[name]; ok {
			if allowOverride {
				logger.Printf("[plugin] override: %q from %s replaces %s", name, p.Source, existing[i].Source)
				existing[i] = p
				continue
			}
			logger.Printf("[plugin] duplicate name %q from %s — keeping %s", name, p.Source, existing[i].Source)
			continue
		}
		existing = append(existing, p)
		idx[name] = len(existing) - 1
	}
	return existing
}

func indexByName(plugins []Plugin) map[string]int {
	idx := make(map[string]int, len(plugins))
	for i, p := range plugins {
		idx[p.Name()] = i
	}
	return idx
}

// discoverDir walks a directory looking for plugin.toml files. The
// dir argument can also point directly at a .toml file, in which case
// just that file is loaded (handy for tests).
func discoverDir(dir, source string, logger *log.Logger) []Plugin {
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Printf("[plugin] cannot read %s: %v", dir, err)
		}
		return nil
	}
	if !info.IsDir() {
		return loadOne(dir, source, logger)
	}

	var out []Plugin
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Printf("[plugin] walk error at %s: %v", path, walkErr)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "plugin.toml" {
			return nil
		}
		out = append(out, loadOne(path, source, logger)...)
		return nil
	})
	if walkErr != nil {
		logger.Printf("[plugin] walk %s: %v", dir, walkErr)
	}
	return out
}

func loadOne(path, source string, logger *log.Logger) []Plugin {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	// Reject symlinked plugin.toml files. Shared with the install
	// flow (feature 0051) via RejectSymlink so both paths use one
	// implementation and one error wording.
	if err := RejectSymlink(abs); err != nil {
		logger.Printf("[plugin] skip %s: %v", abs, err)
		return nil
	}
	m, err := ParseManifest(abs)
	if err != nil {
		logger.Printf("[plugin] skip %s: %v", abs, err)
		return nil
	}
	if err := sanityCheckRuntime(&m, source); err != nil {
		logger.Printf("[plugin] skip %s: %v", abs, err)
		return nil
	}
	return []Plugin{{
		Manifest: m,
		Source:   source,
		Path:     abs,
		Enabled:  true,
	}}
}

// sanityCheckRuntime applies cross-cutting load-time checks the schema
// alone can't enforce: tier=in-tree and runtime.type=in-tree must agree
// in both directions. A third-party manifest claiming runtime.type=
// in-tree could otherwise hijack the in-tree dispatch path; an in-tree
// tier claiming a container runtime would diverge from the synthesised
// virtual manifests and skip the in-tree fast-path checks.
//
// Feature 0053 scopes the second half to non-builtin sources only: a
// manifest discovered from BuiltinDir (Source="builtin") is permitted
// to combine tier=in-tree with a non-in-tree runtime because the
// Vulture release pipeline as a whole vouches for bundled plugins.
// Manifests from any other source (local, env:*) still trip the
// constraint, preserving the security guarantee that an operator-
// installed manifest cannot self-promote to tier=in-tree.
func sanityCheckRuntime(m *Manifest, source string) error {
	if m.Runtime.Type == RuntimeInTree && m.Trust.Tier != TierInTree {
		return fmt.Errorf("runtime.type=in-tree is reserved for first-party manifests (got tier=%s)", m.Trust.Tier)
	}
	if m.Trust.Tier == TierInTree && m.Runtime.Type != RuntimeInTree {
		if source != "builtin" {
			return fmt.Errorf("trust.tier=in-tree requires runtime.type=in-tree for non-builtin sources (got type=%s)", m.Runtime.Type)
		}
	}
	return nil
}
