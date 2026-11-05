package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureUsage returns what printUsage writes to stdout.
func captureUsage(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	printUsage()
	os.Stdout = orig
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Feature 0074: VULTURE_USE_LLM is read with the shared token list
// (config.ParseFlag), so the help must name every accepted "on" token rather
// than imply the switch has to be exactly "true".
func TestUsageNamesUseLLMTokens_0074(t *testing.T) {
	var line string
	for _, l := range strings.Split(captureUsage(t), "\n") {
		if strings.Contains(l, "VULTURE_USE_LLM ") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("help has no VULTURE_USE_LLM line")
	}
	if strings.Contains(line, "true|false") {
		t.Errorf("help still implies true|false only: %q", line)
	}
	if !strings.Contains(line, "true, 1, yes or on") {
		t.Errorf("help does not name the accepted tokens: %q", line)
	}
}
