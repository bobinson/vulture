//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/server"
)

func startTestServer(t *testing.T, cfg *config.Config) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()

	srv := server.New(cfg)
	httpServer := &http.Server{Handler: srv.Handler()}

	go func() {
		_ = httpServer.Serve(listener)
	}()

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}

	return addr, cleanup
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "vulture_test.db")
	return &config.Config{
		Port:   "0",
		DBPath: dbPath,
		Agents: map[string]config.AgentConfig{
			"chaos": {Name: "Chaos Engineering", Type: "chaos", URL: ""},
			"owasp": {Name: "OWASP", Type: "owasp", URL: ""},
			"soc2":  {Name: "SOC2", Type: "soc2", URL: ""},
		},
	}
}

func createTestSourceDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644)
	if err != nil {
		t.Fatalf("write test file: %v", err)
	}
	return dir
}

func httpPost(addr, path string, body interface{}) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return http.Post("http://"+addr+path, "application/json", strings.NewReader(string(b)))
}

func httpGet(addr, path string) (*http.Response, error) {
	return http.Get("http://" + addr + path)
}

func readJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("unmarshal %q: %v", string(body), err)
	}
}
