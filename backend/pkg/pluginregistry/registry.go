package pluginregistry

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

// Registry is the read-only view consumers see. In v1 it is populated
// once at startup; future versions may add hot reload.
type Registry interface {
	All() []Plugin
	Enabled() []Plugin
	ByName(name string) (Plugin, bool)
}

type registry struct {
	plugins []Plugin
}

func (r *registry) All() []Plugin { return r.plugins }

func (r *registry) Enabled() []Plugin {
	out := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}

func (r *registry) ByName(name string) (Plugin, bool) {
	for _, p := range r.plugins {
		if p.Name() == name {
			return p, true
		}
	}
	return Plugin{}, false
}

// Build assembles a Registry from a fresh discovery pass. Each call
// re-reads state.toml — production code generally calls this once at
// startup via Default().
func Build(opts LoadOptions, statePath string) (Registry, error) {
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	plugins := Load(opts)
	state, err := LoadState(statePath)
	if err != nil {
		logger.Printf("[plugin] state load failed; using defaults: %v", err)
		state = StateFile{Plugins: map[string]PluginState{}}
	}
	plugins, state = ApplyState(plugins, state)
	if statePath != "" {
		if err := SaveState(statePath, state); err != nil {
			logger.Printf("[plugin] state save failed (continuing read-only): %v", err)
		}
	}
	// VULTURE_PLUGINS env override: an authoritative activation allow-list for
	// EXTERNAL plugins (in-tree built-in agents are untouched). Applied AFTER
	// SaveState so it is runtime-only and never rewrites state.toml. Absent
	// (unset) => current state.toml behaviour; present (incl. "") => override.
	if spec, ok := os.LookupEnv("VULTURE_PLUGINS"); ok {
		var unknown []string
		plugins, unknown = applyActivationList(plugins, spec)
		if len(unknown) > 0 {
			logger.Printf("[plugin] VULTURE_PLUGINS: ignoring unknown plugin(s): %s", strings.Join(unknown, ", "))
		}
	}
	return &registry{plugins: plugins}, nil
}

// Default returns the process-wide singleton built from
// DefaultLoadOptions + DefaultStatePath. It is built lazily on first
// access. Production code (server.New) typically does not call this
// directly — it builds a Registry via Build and passes the handle
// through dependency injection. Default exists for top-level entry
// points that don't have access to that handle yet.
//
// Concurrency: the singleton is stored in an atomic.Pointer. Build
// runs at most once per ResetDefault cycle, gated by a CAS so racing
// callers see the same instance. Tests that mutate the singleton
// must call ResetDefault under t.Cleanup to avoid cross-test bleed.
func Default() Registry {
	if r := defaultRegistry.Load(); r != nil {
		return *r
	}
	built, err := Build(DefaultLoadOptions(), DefaultStatePath())
	if err != nil {
		log.Printf("[plugin] registry build error: %v", err)
		built = &registry{}
	}
	// CAS: if another goroutine raced us and stored first, drop our
	// instance and return the winner. This keeps "first build wins"
	// behaviour without holding a mutex across the (slow) Build call.
	if !defaultRegistry.CompareAndSwap(nil, &built) {
		return *defaultRegistry.Load()
	}
	return built
}

// ResetDefault clears the cached singleton. Intended for tests only.
// Safe to call concurrently with Default — the next Default call
// will rebuild from current env / disk state.
func ResetDefault() {
	defaultRegistry.Store(nil)
}

// defaultRegistry holds a *Registry (pointer-to-interface) so that
// atomic.Pointer.CompareAndSwap can distinguish "not yet built" (nil)
// from "built but value is the zero Registry". Storing *Registry
// directly would require an atomic.Value with type-shape guarantees;
// the pointer indirection keeps the CAS API clean.
var defaultRegistry atomic.Pointer[Registry]
