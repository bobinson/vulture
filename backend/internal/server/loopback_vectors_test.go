package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The plugin contract's Host rule is this package's isLoopbackHost. One
// committed vector table pins it, and the bundled plugin's Python port is
// tested against the same file, so the two rules cannot drift apart.
func TestIsLoopbackHost_ContractVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "spec", "plugin-v1", "loopback_host_vectors.json"))
	if err != nil {
		t.Fatalf("read vector fixture: %v", err)
	}
	var fixture struct {
		Vectors []struct {
			Host     string `json:"host"`
			Loopback bool   `json:"loopback"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode vector fixture: %v", err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("the vector fixture holds no vectors")
	}
	for _, v := range fixture.Vectors {
		if got := isLoopbackHost(v.Host); got != v.Loopback {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", v.Host, got, v.Loopback)
		}
	}
}
