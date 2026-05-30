package main

import (
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/vulture/backend/pkg/pluginregistry"
)

func cmdPluginList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plugin list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	pluginsDir := resolvePluginsDir()
	plugins := pluginregistry.Load(pluginregistry.LoadOptions{
		LocalDir:       pluginsDir,
		IncludeVirtual: true,
	})
	state, err := loadStateOrEmpty(stateFilePath())
	if err != nil {
		fmt.Fprintf(stderr, "plugin list: %v\n", err)
		return 1
	}
	printPluginTable(stdout, plugins, state)
	return 0
}

func printPluginTable(out io.Writer, plugins []pluginregistry.Plugin, state pluginregistry.StateFile) {
	if len(plugins) == 0 {
		fmt.Fprintln(out, "No plugins installed.")
		return
	}
	rows := make([]pluginregistry.Plugin, len(plugins))
	copy(rows, plugins)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name() < rows[j].Name() })
	fmt.Fprintf(out, "%-24s %-18s %-10s %s\n", "NAME", "TIER", "ENABLED", "SOURCE")
	for _, p := range rows {
		enabled := "yes"
		if st, ok := state.Plugins[p.Name()]; ok && !st.Enabled {
			enabled = "no"
		}
		fmt.Fprintf(out, "%-24s %-18s %-10s %s\n",
			p.Name(), p.Manifest.Trust.Tier, enabled, p.Source)
	}
}
