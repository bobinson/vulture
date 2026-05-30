package main

import (
	"fmt"
	"io"
)

// pluginSubcommands is the dispatch table for `vulture plugin <sub>`.
// Keeps dispatchPlugin under the cyclomatic-complexity cap.
var pluginSubcommands = map[string]func([]string, io.Writer, io.Writer) int{
	"list":    cmdPluginList,
	"install": cmdPluginInstall,
	"enable":  cmdPluginEnable,
	"disable": cmdPluginDisable,
	"remove":  cmdPluginRemove,
	"verify":  cmdPluginVerify,
	"info":    cmdPluginInfo,
}

// helpRequested reports whether the user invoked plugin help (no args,
// `help`, `-h`, `--help`).
func helpRequested(args []string) bool {
	if len(args) < 2 {
		return true
	}
	switch args[1] {
	case "help", "-h", "--help":
		return true
	}
	return false
}

// dispatchPlugin parses `vulture plugin <subcommand>` argv and routes
// to per-subcommand handlers. Returns the process exit code; never
// calls os.Exit so callers (tests + main) can compose freely.
//
// The args slice starts with "plugin" (i.e. callers pass
// os.Args[1:]). This matches the test fixtures.
func dispatchPlugin(args []string, stdout, stderr io.Writer) int {
	if helpRequested(args) {
		printPluginHelp(stdout)
		return 0
	}
	sub := args[1]
	if handler, ok := pluginSubcommands[sub]; ok {
		return handler(args[2:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown plugin subcommand: %s\n", sub)
	printPluginHelp(stderr)
	return 1
}

func printPluginHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: vulture plugin <subcommand> [options]

Subcommands:
  list                List installed plugins and their status
  install <path>      Install a plugin from a local manifest path
  enable  <name>      Enable an installed plugin
  disable <name>      Disable an installed plugin (keeps files on disk)
  remove  <name>      Remove an installed plugin (files + state entry)
  verify  <name>      Re-run cosign verify on an installed community-signed plugin
  info    <name>      Show full manifest + verification status

Each subcommand accepts --help for its own flags.`)
}
