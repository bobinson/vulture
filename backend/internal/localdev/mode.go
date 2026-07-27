package localdev

import (
	"path/filepath"

	"github.com/vulture/backend/pkg/vhome"
)

// Mode discriminates between an installed Vulture (Mode E: native
// installer) and a source-checkout dev workflow. The switch is the
// presence of a VERSION file at the resolved Vulture home.
type Mode int

const (
	ModeDev Mode = iota
	ModeInstall
)

func (m Mode) String() string {
	if m == ModeInstall {
		return "install"
	}
	return "dev"
}

// ResolveHome returns the VULTURE_HOME path. Honors the env var first,
// then falls back to $HOME/.vulture. Returns the empty string only if
// neither is available, which the caller treats as "use dev mode".
//
// Delegates to pkg/vhome — the single source of truth shared with the CLI
// (a separate module that cannot import this internal package).
func ResolveHome() string {
	return vhome.Home()
}

// DetectMode returns ModeInstall if VULTURE_HOME/VERSION exists,
// ModeDev otherwise. Errors during stat are treated as "not installed".
//
// Delegates the install-vs-dev decision to pkg/vhome; this wrapper only maps
// the boolean onto the localdev.Mode type used throughout the backend.
func DetectMode() Mode {
	if vhome.IsInstall() {
		return ModeInstall
	}
	return ModeDev
}

// RuntimeRoot returns the runtime asset root for the given mode.
// In install mode this is $VULTURE_HOME/runtime; in dev mode the
// caller supplies the project root (returned unchanged).
func RuntimeRoot(mode Mode, projectRoot string) string {
	if mode == ModeInstall {
		return filepath.Join(ResolveHome(), "runtime")
	}
	return projectRoot
}

// DataDir returns the mutable data root for the given mode.
// Install mode: $VULTURE_HOME/data.  Dev mode: <projectRoot>/data
// (matching existing local-dev convention).
func DataDir(mode Mode, projectRoot string) string {
	if mode == ModeInstall {
		return filepath.Join(ResolveHome(), "data")
	}
	return filepath.Join(projectRoot, "data")
}

// ConfigDir returns the config directory for the given mode.
func ConfigDir(mode Mode, projectRoot string) string {
	if mode == ModeInstall {
		return filepath.Join(ResolveHome(), "config")
	}
	return projectRoot
}

// PythonBin returns the absolute path to the python interpreter the
// launcher should use to spawn agents. In install mode this is the
// bundled python-build-standalone under runtime/python; in dev mode
// the caller is expected to use the system python (returned as an
// empty string here so the launcher falls back to its detect logic).
func PythonBin(mode Mode) string {
	if mode == ModeInstall {
		return filepath.Join(ResolveHome(), "runtime", "python", "bin", "python3.12")
	}
	return ""
}

// UIPort returns the port that serves the web UI for the given mode.
// In install mode there is ONE server: the backend on cfg.BackendPort serves
// both the API and the embedded SPA, so the UI lives at the backend port. In
// dev mode the UI is the separate vite dev server on cfg.FrontendPort.
func UIPort(mode Mode, cfg *Config) string {
	if mode == ModeInstall {
		return cfg.BackendPort
	}
	return cfg.FrontendPort
}

// AgentsRoot returns the directory containing per-agent Python source.
func AgentsRoot(mode Mode, projectRoot string) string {
	if mode == ModeInstall {
		return filepath.Join(ResolveHome(), "runtime", "agents")
	}
	return filepath.Join(projectRoot, "agents")
}
