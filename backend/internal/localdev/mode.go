package localdev

import (
	"os"
	"path/filepath"
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
func ResolveHome() string {
	if h := os.Getenv("VULTURE_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vulture")
}

// DetectMode returns ModeInstall if VULTURE_HOME/VERSION exists,
// ModeDev otherwise. Errors during stat are treated as "not installed".
func DetectMode() Mode {
	home := ResolveHome()
	if home == "" {
		return ModeDev
	}
	info, err := os.Stat(filepath.Join(home, "VERSION"))
	if err != nil || info.IsDir() {
		return ModeDev
	}
	return ModeInstall
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

// AgentsRoot returns the directory containing per-agent Python source.
func AgentsRoot(mode Mode, projectRoot string) string {
	if mode == ModeInstall {
		return filepath.Join(ResolveHome(), "runtime", "agents")
	}
	return filepath.Join(projectRoot, "agents")
}
