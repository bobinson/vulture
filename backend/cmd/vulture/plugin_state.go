package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vulture/backend/pkg/pluginregistry"
)

func cmdPluginEnable(args []string, stdout, stderr io.Writer) int {
	return setEnabled(args, true, "enable", stdout, stderr)
}

func cmdPluginDisable(args []string, stdout, stderr io.Writer) int {
	return setEnabled(args, false, "disable", stdout, stderr)
}

func setEnabled(args []string, want bool, verb string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plugin "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() < 1 {
		fmt.Fprintf(stderr, "usage: vulture plugin %s <name>\n", verb)
		return 1
	}
	name := fs.Arg(0)
	statePath := stateFilePath()
	if statePath == "" {
		fmt.Fprintln(stderr, "plugin "+verb+": cannot resolve plugins dir")
		return 1
	}
	state, err := loadStateOrEmpty(statePath)
	if err != nil {
		fmt.Fprintf(stderr, "plugin %s: %v\n", verb, err)
		return 1
	}
	ps, ok := state.Plugins[name]
	if !ok {
		ps = pluginregistry.PluginState{InstalledAt: time.Now().UTC()}
	}
	ps.Enabled = want
	state.Plugins[name] = ps
	if err := pluginregistry.SaveState(statePath, state); err != nil {
		fmt.Fprintf(stderr, "plugin %s: %v\n", verb, err)
		return 1
	}
	fmt.Fprintf(stdout, "Plugin %q %sd\n", name, verb)
	return 0
}

func cmdPluginRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plugin remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: vulture plugin remove <name>")
		return 1
	}
	name := fs.Arg(0)
	pluginsDir := resolvePluginsDir()
	if pluginsDir == "" {
		fmt.Fprintln(stderr, "plugin remove: cannot resolve plugins dir")
		return 1
	}
	pluginDir := filepath.Join(pluginsDir, name)
	if err := os.RemoveAll(pluginDir); err != nil {
		fmt.Fprintf(stderr, "plugin remove: rmdir %s: %v\n", pluginDir, err)
		return 1
	}
	statePath := filepath.Join(pluginsDir, "state.toml")
	state, err := loadStateOrEmpty(statePath)
	if err != nil {
		fmt.Fprintf(stderr, "plugin remove: %v\n", err)
		return 1
	}
	delete(state.Plugins, name)
	if err := pluginregistry.SaveState(statePath, state); err != nil {
		fmt.Fprintf(stderr, "plugin remove: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Removed: %s\n", name)
	return 0
}
