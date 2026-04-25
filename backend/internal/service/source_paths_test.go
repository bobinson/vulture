package service

import (
	"strings"
	"testing"
)

func TestSourceRunDir_WithRunID(t *testing.T) {
	got := SourceRunDir("/tmp/sources", "src-abc", "run-xyz")
	if !strings.HasSuffix(got, "/src-abc/run-run-xyz") {
		t.Fatalf("unexpected path: %s", got)
	}
}

func TestSourceRunDir_EmptyRunIDFallsBack(t *testing.T) {
	got := SourceRunDir("/tmp/sources", "src-abc", "")
	if !strings.HasSuffix(got, "/src-abc") {
		t.Fatalf("expected fallback to source-id only: %s", got)
	}
}

func TestSourceRunDir_DifferentRunsProduceDifferentPaths(t *testing.T) {
	a := SourceRunDir("/tmp/sources", "src-abc", "run-1")
	b := SourceRunDir("/tmp/sources", "src-abc", "run-2")
	if a == b {
		t.Fatal("different runs must produce different paths")
	}
}
