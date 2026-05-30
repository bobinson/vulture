package pluginlifecycle_test

// AC14: permission constants are defined in pkg/pluginregistry and
// re-used by lifecycle code. Tests pin the values from the LLD:
//   PluginDirMode  = 0o700  per-plugin dir
//   ManifestMode   = 0o644  plugin.toml
//   StateFileMode  = 0o600  state.toml
//   MarkerMode     = 0o600  .cosign-verified
//
// This file fails to compile until production code declares the
// exported constants. That's the RED state we want.

import (
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

func TestPermissionConstants_AC14(t *testing.T) {
	cases := []struct {
		name string
		got  interface{}
		want uint32
	}{
		{"PluginDirMode", uint32(pluginregistry.PluginDirMode), 0o700},
		{"ManifestMode", uint32(pluginregistry.ManifestMode), 0o644},
		{"StateFileMode", uint32(pluginregistry.StateFileMode), 0o600},
		{"MarkerMode", uint32(pluginregistry.MarkerMode), 0o600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ok := tc.got.(uint32)
			if !ok {
				t.Fatalf("%s: unexpected type %T", tc.name, tc.got)
			}
			if g != tc.want {
				t.Errorf("%s = 0o%o, want 0o%o", tc.name, g, tc.want)
			}
		})
	}
}
