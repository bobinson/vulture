package pluginregistry

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// StateFile is the parsed `state.toml` mapping plugin names to their
// per-install state. The schema is intentionally tiny so an operator
// can edit it by hand.
type StateFile struct {
	Plugins map[string]PluginState `toml:"plugins"`
}

// PluginState captures the operator-controlled bits for one plugin.
type PluginState struct {
	Enabled     bool      `toml:"enabled"`
	TrustAcks   []string  `toml:"trust_acks"`
	InstalledAt time.Time `toml:"installed_at"`
}

// LoadState reads state.toml. A missing file is treated as an empty
// state (every plugin discovered later will default to enabled).
func LoadState(path string) (StateFile, error) {
	if path == "" {
		return StateFile{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return StateFile{}, nil
		}
		return StateFile{}, fmt.Errorf("read state %s: %w", path, err)
	}
	var s StateFile
	if _, err := toml.Decode(string(data), &s); err != nil {
		return StateFile{}, fmt.Errorf("decode state %s: %w", path, err)
	}
	if s.Plugins == nil {
		s.Plugins = map[string]PluginState{}
	}
	return s, nil
}

// SaveState atomically writes state.toml with 0600 permissions. The
// encode happens into a `.tmp` sibling, then `os.Rename` swaps it
// into place. If the encode fails partway, the prior state.toml is
// untouched — operator-configured enable/disable flags are never
// silently wiped by a half-written file.
func SaveState(path string, s StateFile) error {
	if path == "" {
		return errors.New("state path empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.toml")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename.
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(StateFileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp state: %w", err)
	}
	if err := toml.NewEncoder(tmp).Encode(s); err != nil {
		tmp.Close()
		return fmt.Errorf("encode state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

// ApplyState marks each plugin's Enabled flag according to the state
// file. Newly-discovered plugins (not in state) default to enabled.
// Returns the updated state with default rows added for any missing
// plugin so the caller can persist a complete record.
func ApplyState(plugins []Plugin, s StateFile) ([]Plugin, StateFile) {
	if s.Plugins == nil {
		s.Plugins = map[string]PluginState{}
	}
	now := time.Now().UTC()
	for i := range plugins {
		name := plugins[i].Name()
		st, ok := s.Plugins[name]
		if !ok {
			st = PluginState{Enabled: true, InstalledAt: now}
			s.Plugins[name] = st
		}
		plugins[i].Enabled = st.Enabled
	}
	return plugins, s
}

// DefaultStatePath returns ~/.vulture/plugins/state.toml or "" if
// HOME is unknown.
func DefaultStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vulture", "plugins", "state.toml")
}
