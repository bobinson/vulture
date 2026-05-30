package main

// CLI argv-dispatch seam.
//
// The LLD pins (Architecture + "Maintenance" sections) that each
// subcommand owns its own flag.FlagSet, and that the dispatcher is a
// thin argv-to-function shim. For testability, the dispatcher MUST
// be a callable function that returns an int (exit code) and accepts
// io.Writer for stdout + stderr so process spawn is not required.
//
// Pinned signature for this seam:
//   func dispatchPlugin(args []string, stdout, stderr io.Writer) int
//
// The GREEN agent will add this function in cmd/vulture/plugin.go and
// wire main.go's "plugin" switch case to call it (passing os.Stdout /
// os.Stderr / os.Args[1:]).

import (
	"bytes"
	"strings"
	"testing"
)

func TestDispatchPlugin_HelpExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := dispatchPlugin([]string{"plugin"}, &stdout, &stderr)
	if rc != 0 {
		t.Errorf("rc=%d want 0; stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
	}
	// Help text should mention the seven subcommands.
	all := stdout.String() + stderr.String()
	for _, sub := range []string{"list", "install", "enable", "disable", "remove", "verify", "info"} {
		if !strings.Contains(all, sub) {
			t.Errorf("plugin help missing subcommand %q (got %q)", sub, all)
		}
	}
}

func TestDispatchPlugin_HelpFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := dispatchPlugin([]string{"plugin", "--help"}, &stdout, &stderr)
	if rc != 0 {
		t.Errorf("--help rc=%d want 0", rc)
	}
}

func TestDispatchPlugin_UnknownSubcommandExitsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := dispatchPlugin([]string{"plugin", "frobnicate"}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("expected non-zero for unknown subcommand")
	}
}

func TestDispatchPlugin_InstallMissingArgExitsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := dispatchPlugin([]string{"plugin", "install"}, &stdout, &stderr)
	if rc == 0 {
		t.Errorf("install without path should fail")
	}
}

func TestDispatchPlugin_InstallNonexistentPathExitsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := dispatchPlugin(
		[]string{"plugin", "install", "/nonexistent/definitely/not/a/path/here"},
		&stdout, &stderr,
	)
	if rc == 0 {
		t.Errorf("install with nonexistent path should fail")
	}
}

func TestDispatchPlugin_ListSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// list should at minimum succeed (rc=0) on a fresh / empty plugins dir.
	// VULTURE_PLUGINS_DIR isn't set, so the implementation should fall
	// back to a default (probably ~/.vulture/plugins which may not
	// exist — that should be a clean "no plugins" output, NOT a crash).
	rc := dispatchPlugin([]string{"plugin", "list"}, &stdout, &stderr)
	if rc != 0 {
		t.Errorf("list rc=%d want 0; stderr=%q", rc, stderr.String())
	}
}
