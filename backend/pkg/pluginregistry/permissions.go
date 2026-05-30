package pluginregistry

// File-mode constants used by the plugin registry and lifecycle code.
// Feature 0051 MAJOR 10: a single source of truth so no caller hard-codes
// 0o600 / 0o644 / 0o700 in production code paths.
const (
	// PluginDirMode is the mode for each per-plugin directory under
	// ~/.vulture/plugins/<name>/. 0700 keeps verification metadata
	// readable only by the operator.
	PluginDirMode = 0o700

	// ManifestMode is the mode for plugin.toml files copied into the
	// install dir. 0644: world-readable, owner-writable; manifests
	// carry no secrets.
	ManifestMode = 0o644

	// StateFileMode is the mode for ~/.vulture/plugins/state.toml.
	// 0600: this file records operator-chosen trust acknowledgements
	// (e.g. acceptance of `runs-real-exploits`) — protect from other
	// users on shared hosts.
	StateFileMode = 0o600

	// MarkerMode is the mode for the per-plugin .cosign-verified
	// marker file. 0600 for the same reason as state.toml: subject
	// URLs and signer identities can be operationally sensitive.
	MarkerMode = 0o600
)
