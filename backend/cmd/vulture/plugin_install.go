package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vulture/backend/internal/pluginlifecycle"
	"github.com/vulture/backend/pkg/pluginregistry"
)

func cmdPluginInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plugin install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	assumeYes := fs.Bool("yes", false, "non-interactive confirmation of any required acks")
	cosignBinary := fs.String("cosign", "", "path to cosign binary (overrides VULTURE_COSIGN_BINARY / PATH)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: vulture plugin install [--yes] [--cosign PATH] <plugin.toml|dir>")
		return 1
	}
	pluginsDir := resolvePluginsDir()
	if pluginsDir == "" {
		fmt.Fprintln(stderr, "plugin install: cannot resolve plugins dir (set VULTURE_PLUGINS_DIR or HOME)")
		return 1
	}
	opts := pluginlifecycle.InstallOptions{
		SourcePath:   fs.Arg(0),
		PluginsDir:   pluginsDir,
		StatePath:    filepath.Join(pluginsDir, "state.toml"),
		AssumeYes:    *assumeYes,
		In:           os.Stdin,
		Out:          stdout,
		CosignBinary: *cosignBinary,
	}
	res, err := pluginlifecycle.Install(opts)
	if err != nil {
		fmt.Fprintf(stderr, "plugin install: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Installed: %s\n", res.PluginPath)
	if res.Verified {
		fmt.Fprintf(stdout, "Cosign verified; marker: %s\n", res.MarkerPath)
	}
	fmt.Fprintln(stdout, "Restart the backend to activate.")
	return 0
}

// resolvePluginsDir picks the install root: env override > default
// (~/.vulture/plugins). Empty string when neither is available.
func resolvePluginsDir() string {
	if env := os.Getenv("VULTURE_PLUGINS_DIR"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vulture", "plugins")
}

// stateFilePath returns the canonical state.toml path under
// resolvePluginsDir, used by enable/disable/remove/list.
func stateFilePath() string {
	dir := resolvePluginsDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "state.toml")
}

// loadStateOrEmpty wraps LoadState and returns an empty state if the
// file is missing — so `plugin list` on a fresh system prints cleanly.
func loadStateOrEmpty(path string) (pluginregistry.StateFile, error) {
	st, err := pluginregistry.LoadState(path)
	if err != nil {
		return pluginregistry.StateFile{}, err
	}
	if st.Plugins == nil {
		st.Plugins = map[string]pluginregistry.PluginState{}
	}
	return st, nil
}
