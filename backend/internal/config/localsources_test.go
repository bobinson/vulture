package config

import (
	"testing"

	"github.com/vulture/backend/internal/pathutil"
)

// TestConfigLocalSources_Delegates: the config exposes the local-path policy
// by delegating to pathutil.NewLocalSources with its own SourceRoot, LocalMode
// and ReadOnly, for all eight combinations, so no caller derives it twice.
func TestConfigLocalSources_Delegates(t *testing.T) {
	roots := [2]string{"", "/srv/vulture/sources"}
	for i := 0; i < 8; i++ {
		c := &Config{SourceRoot: roots[i&1], LocalMode: i&2 != 0, ReadOnly: i&4 != 0}
		want := pathutil.NewLocalSources(c.SourceRoot, c.LocalMode, c.ReadOnly)
		if got := c.LocalSources(); got != want {
			t.Errorf("Config{SourceRoot: %q, LocalMode: %v, ReadOnly: %v}.LocalSources() = %+v; want %+v",
				c.SourceRoot, c.LocalMode, c.ReadOnly, got, want)
		}
	}
}
