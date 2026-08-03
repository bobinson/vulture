package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/llm"
	"github.com/vulture/backend/internal/localdev"
	"github.com/vulture/backend/internal/server"
	"github.com/vulture/backend/pkg/gitutil"
)

// Version is the build version reported by `vulture version`. It defaults to a
// "dev" sentinel and is overridden at release-build time via the linker:
//
//	go build -ldflags "-X main.Version=<git-tag>" ...
//
// (scripts/build-release.sh injects ${VERSION}). The symbol name here MUST stay
// `main.Version` to match that ldflag — otherwise the injection is a silent
// no-op and the binary misreports its version. 0055 follow-up.
var Version = "dev"

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
		fmt.Println("vulture " + Version)
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
  VULTURE_USE_LLM          Enable LLM analysis (true|false; default false = skills-only)
  VULTURE_LLM_MODEL        LLM model name (e.g. gpt-4o, claude-sonnet, gemini-pro, qwen3:1.7b)
  OPENAI_API_KEY           API key for OpenAI / OpenAI-compatible LLM audits
  OPENAI_BASE_URL          Custom OpenAI-compatible endpoint (LM Studio, vLLM, proxies)
  ANTHROPIC_API_KEY        API key for Claude models
  GEMINI_API_KEY           API key for Google Gemini models
  OLLAMA_API_BASE          Ollama endpoint for local models (default http://localhost:11434)

In install mode these may also be set in $VULTURE_HOME/config/.env (loaded at
'vulture start'). Run 'vulture doctor' to see the resolved LLM provider/model.`)
}

// llmEndpointStartupError validates the long-lived-provider-key-bearing LLM
// endpoints at startup (0065 §2.2/§H5, F10). It checks OPENAI_BASE_URL and
// VULTURE_EMBEDDING_URL ONLY — internal agent-proxy and LLM-broker URLs are
// intentionally excluded (§R2). It returns a non-nil boot error only under
// VULTURE_STRICT_LLM_ENDPOINT; the default degrades with a WARN and returns nil
// (the embedding sink guard withholds the key either way). Extracted as a
// testable seam so the strict/degrade branch and the §R2 exclusion are covered.
func llmEndpointStartupError() error {
	if config.EnvTruthy("VULTURE_ALLOW_INSECURE_LLM") {
		return nil
	}
	endpoints := map[string]string{
		"OPENAI_BASE_URL":       os.Getenv("OPENAI_BASE_URL"),
		"VULTURE_EMBEDDING_URL": os.Getenv("VULTURE_EMBEDDING_URL"),
	}
	if err := llm.ValidateAll(endpoints); err != nil {
		if config.EnvTruthy("VULTURE_STRICT_LLM_ENDPOINT") {
			return fmt.Errorf("insecure LLM endpoint (strict mode): %w", err)
		}
		log.Printf("WARN insecure LLM endpoint: %v — continuing; API keys will NOT be sent over it (set VULTURE_STRICT_LLM_ENDPOINT=true to hard-fail, or VULTURE_ALLOW_INSECURE_LLM=true to allow)", err)
	}
	return nil
}

func runServer() {
	cfg := config.Load()
	// 0065 §2.2 (F10, §H5): validate the long-lived-provider-key-bearing
	// LLM endpoints only. Internal service-mesh URLs (agent-proxy and the
	// LLM-broker) are intentionally excluded (§R2): they are legitimately
	// http:// to internal hosts and carry short-lived internal tokens, not
	// the provider key this check protects. Degrade-with-warning by default
	// (the embedding sink guard already prevents the key leak); hard-fail
	// only when VULTURE_STRICT_LLM_ENDPOINT=true.
	if err := llmEndpointStartupError(); err != nil {
		log.Fatalf("%v", err)
	}
	// 0065 §L2: probe OpenSSH; if too old for accept-new, fall back to
	// strict=yes behind the persistent known_hosts and warn prominently.
	if warn := gitutil.EnsureSSHStrictCompat(context.Background(), os.Setenv); warn != "" {
		log.Println(warn)
	}
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	// 0036 Phase 3 (H9): cfg.ListenAddr is resolved by config.Load to
	// 127.0.0.1:<port> when VULTURE_LOCAL_MODE=true, falling back to
	// :<port> (all interfaces) for Mode-B reverse-proxy deployments.
	// Operator override via VULTURE_LISTEN_ADDR. server.New validates
	// the loopback constraint and refuses to start if violated.
	addr := cfg.ListenAddr
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

	// Feature 0064 §25.2: when the LLM broker is enabled, serve it on a
	// SEPARATE internal-only listener (never behind the public CORS/SPA
	// middleware, and never ingress-exposed — §11). Off → nothing starts.
	var brokerSrv *http.Server
	if b := srv.Broker(); b != nil && b.Enabled {
		brokerSrv = &http.Server{
			Addr:              cfg.Broker.Listen,
			Handler:           b.Handler,
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		go func() {
			log.Printf("vulture llm-broker (internal) starting on %s", cfg.Broker.Listen)
			if err := brokerSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("broker server error: %v", err)
			}
		}()
	}

	<-done
	log.Println("shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Fatalf("forced shutdown: %v", err)
	}
	if brokerSrv != nil {
		_ = brokerSrv.Shutdown(ctx)
		srv.Broker().Close() // stop the lease sweeper
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
		"backend": cfg.Port,
	}
	// In install mode the backend serves the UI directly (embedded SPA) — there
	// is no separate frontend server listening on FrontendPort, so don't probe
	// a row that will always read DOWN. Dev mode runs the vite dev server.
	if localdev.DetectMode() == localdev.ModeDev {
		ports["frontend"] = lcfg.FrontendPort
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

	// Scan guard: with no agent runtime reachable, NOTHING scans (skills run
	// inside the Python agents). Warn loudly but continue, so submissions to a
	// remote/centralized server still work.
	warnIfNoAgentsReachable(cfg)

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

	// Trigger + run the audit. A plain audit is not auto-run on creation;
	// opening its stream is what kicks off the run on the backend. Drain it
	// to completion, then print a result summary (Feature 0055 — previously
	// the CLI submitted and exited, leaving the audit stuck 'pending').
	fmt.Println("\nRunning audit...")
	if err := runAuditViaStream(apiURL, auditID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: run/stream: %v\n", err)
	}
	if status, total, byAgent, err := auditSummary(apiURL, auditID); err == nil {
		fmt.Printf("Status: %s | findings: %d\n", status, total)
		if total > 0 {
			fmt.Printf("By agent: %v\n", byAgent)
		}
	}

	mode := localdev.DetectMode()
	lcfg := localdev.DefaultConfig(findProjectRoot())
	fmt.Printf("View results: %s\n", auditResultsURL(apiURL, mode, lcfg, auditID))
}

// auditResultsURL builds the "View results" link from the origin the scan
// ACTUALLY used, not from a freshly-defaulted config.
//
// The previous version re-derived host and port from localdev.DefaultConfig,
// which discarded both VULTURE_API_URL and the real backend port — so a scan
// against a non-default port or a remote server printed a link to
// http://localhost:<default>. In dev mode it was also silently wrong whenever
// the command ran outside the project tree, because findProjectRoot() cannot
// locate config.ini from there and every port falls back to its default.
//
// Install mode serves the UI from the backend, so the API origin is the UI
// origin. Dev mode runs a separate frontend dev server on the same host, so the
// host is taken from the API and only the port is swapped.
func auditResultsURL(
	apiURL string, mode localdev.Mode, cfg *localdev.Config, auditID string,
) string {
	path := "/audit/" + auditID
	if env := os.Getenv("VULTURE_FRONTEND_URL"); env != "" {
		return strings.TrimRight(env, "/") + path
	}
	fallback := "http://localhost:" + cfg.FrontendPort + path
	if mode == localdev.ModeInstall {
		fallback = "http://localhost:" + cfg.BackendPort + path
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return fallback
	}
	// A remote backend serves its own SPA, and so does a native install — in
	// both cases the API origin IS the UI origin. Only a loopback dev split has
	// the SPA on a separate vite port. Same rule as the `cli` binary's uiURL();
	// the two disagreed before this, which is how the divergence was noticed.
	if mode == localdev.ModeInstall || !isLoopbackHost(u.Hostname()) {
		u.User = nil // never leak credentials from --server into a printed link
		u.RawQuery, u.Fragment = "", ""
		return strings.TrimRight(u.String(), "/") + path
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), cfg.FrontendPort) + path
}

// isLoopbackHost reports whether host is localhost or any loopback IP, i.e. a
// backend co-located with this CLI.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnIfNoAgentsReachable probes every configured agent's /health endpoint with
// a short timeout. If ZERO are reachable, it prints a loud, actionable warning:
// with no agent runtime the scan produces no findings (skills run inside the
// agents). It warns rather than refusing, so remote/centralized submissions
// still work.
func warnIfNoAgentsReachable(cfg *config.Config) {
	client := &http.Client{Timeout: 1 * time.Second}
	// Install/local mode: agents run as native processes on localhost:<port>.
	// Probe those FIRST — cfg.Agents[*].URL carries docker-compose hostnames
	// (http://agent-chaos:NNNN) that never resolve on the host, which made
	// this warning a false negative (and the scan a no-op) on native installs.
	lcfg := localdev.DefaultConfig(findProjectRoot())
	for _, port := range lcfg.AgentPorts {
		if port == "" {
			continue
		}
		resp, err := client.Get("http://localhost:" + port + "/health")
		if err == nil {
			resp.Body.Close()
			return // at least one agent reachable
		}
	}
	// Fall back to the configured agent URLs (docker-compose / Mode B).
	for _, agent := range cfg.Agents {
		resp, err := client.Get(agent.URL + "/health")
		if err == nil {
			resp.Body.Close()
			return
		}
	}
	fmt.Fprintln(os.Stderr,
		"WARNING: no audit agents are reachable at the local API — this scan will produce "+
			"NO findings. Install Python 3.12+ and reinstall (or set VULTURE_USE_SYSTEM_PYTHON=1), "+
			"or use Docker (Mode A/B) for agent scanning. Continuing anyway "+
			"(a remote/centralized server may still process this submission).")
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
