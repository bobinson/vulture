package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/localdev"
	"github.com/vulture/backend/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		runServer()
		return
	}

	switch os.Args[1] {
	case "serve", "server":
		runServer()
	case "local_start", "local-start":
		runLocalStart()
	case "status":
		runStatus()
	case "scan":
		runScan()
	case "start":
		runStart()
	case "stop":
		runStop()
	case "logs":
		runLogs()
	case "doctor":
		runDoctor()
	case "uninstall":
		runUninstall()
	case "plugin":
		os.Exit(dispatchPlugin(os.Args[1:], os.Stdout, os.Stderr))
	case "version":
		fmt.Println("vulture v0.1.0")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: vulture <command> [options]

Commands:
  serve          Start the backend HTTP server (default)
  local_start    Launch all components locally (backend + agents + frontend)
  scan <path>    Quick-scan a local path or git URL
  status         Show status of running services
  start          Start the daemon (install mode: backgrounds; dev mode: foreground)
  stop           Stop the daemon (verifies cmdline before SIGTERM — S4)
  logs [agent]   Tail data/logs/<name>.log through the redactor
  doctor         Diagnose install health (Python, modes, ports, audit log)
  uninstall      Remove the install (install mode only)
  plugin         Manage plugins (install/list/enable/disable/remove/verify/info)
  version        Print version
  help           Show this help

Environment:
  VULTURE_PORT             Backend port (default: from config.ini)
  VULTURE_DB_PATH          SQLite database path (default: /data/vulture.db)
  VULTURE_DB_DSN           PostgreSQL DSN (if set, uses Postgres instead of SQLite)
  OPENAI_API_KEY           API key for LLM-powered audits
  VULTURE_LLM_MODEL        LLM model name (default: gpt-4o)`)
}

func runServer() {
	cfg := config.Load()
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	addr := ":" + cfg.Port
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // Disabled — SSE streams can run for hours
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("vulture backend starting on %s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-done
	log.Println("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Fatalf("forced shutdown: %v", err)
	}
	// Feature 0052: stop supervised container plugins before exiting.
	// StopAll respects each plugin's runtime.restart policy
	// (containers with restart=always/unless-stopped are intentionally
	// left running across backend restarts).
	if sup := srv.Supervisor(); sup != nil {
		if err := sup.StopAll(ctx); err != nil {
			log.Printf("supervisor stop-all: %v", err)
		}
	}
	log.Println("server stopped")
}

func runLocalStart() {
	projectRoot := findProjectRoot()
	cfg := localdev.DefaultConfig(projectRoot)
	launcher := localdev.NewLauncher(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	if err := launcher.Start(ctx); err != nil {
		log.Fatalf("local start failed: %v", err)
	}

	<-done
	fmt.Println("\nshutting down all services...")
	cancel()
	launcher.Manager().WaitAll()
	fmt.Println("all services stopped")
}

func runStatus() {
	cfg := config.Load()
	lcfg := localdev.DefaultConfig(findProjectRoot())
	ports := map[string]string{
		"backend":  cfg.Port,
		"frontend": lcfg.FrontendPort,
	}
	for name, agent := range cfg.Agents {
		// Extract port from URL like "http://agent-chaos:28001"
		parts := strings.Split(agent.URL, ":")
		if len(parts) == 3 {
			ports["agent-"+name] = parts[2]
		}
	}

	fmt.Println("Vulture Service Status")
	fmt.Println("======================")
	for name, port := range ports {
		status := checkHealth("http://localhost:" + port)
		fmt.Printf("  %-15s :%s  %s\n", name, port, status)
	}
}

func runScan() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: vulture scan <path_or_url>")
		os.Exit(1)
	}
	target := os.Args[2]
	cfg := config.Load()
	apiURL := os.Getenv("VULTURE_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:" + cfg.Port
	}

	fmt.Printf("Scanning: %s\n", target)
	fmt.Printf("API: %s\n", apiURL)

	// Determine source type
	sourceType := "local"
	if isGitURL(target) {
		sourceType = "git"
	}

	// Submit source
	sourceID, err := submitSource(apiURL, sourceType, target)
	if err != nil {
		log.Fatalf("submit source: %v", err)
	}
	fmt.Printf("Source ID: %s\n", sourceID)

	// Create audit with all configured agent types (excluding prove — it runs post-audit)
	auditTypes := make([]string, 0, len(cfg.Agents))
	for agentType := range cfg.Agents {
		if agentType != "prove" {
			auditTypes = append(auditTypes, agentType)
		}
	}
	auditID, err := createAudit(apiURL, sourceID, auditTypes)
	if err != nil {
		log.Fatalf("create audit: %v", err)
	}
	fmt.Printf("Audit ID: %s\n", auditID)
	fmt.Printf("\nView results: http://localhost:%s/audit/%s\n",
		localdev.DefaultConfig(findProjectRoot()).FrontendPort, auditID)
	fmt.Printf("Stream API:   %s/api/audits/%s/stream\n", apiURL, auditID)
}

func findProjectRoot() string {
	// Check if we're inside the vulture project
	cwd, _ := os.Getwd()
	candidates := []string{
		cwd,
		filepath.Join(cwd, ".."),
		filepath.Join(cwd, "../.."),
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "backend")); err == nil {
				abs, _ := filepath.Abs(dir)
				return abs
			}
		}
	}
	return cwd
}

func checkHealth(url string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/health")
	if err != nil {
		return "DOWN"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return "UP"
	}
	return fmt.Sprintf("ERROR (%d)", resp.StatusCode)
}

func isGitURL(s string) bool {
	for _, prefix := range []string{"http://", "https://", "git@", "ssh://"} {
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
