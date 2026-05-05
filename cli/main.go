package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vulture/backend/pkg/agentregistry"
	"github.com/vulture/backend/pkg/iniutil"
	"golang.org/x/term"
)

const (
	configDir = ".vulture"
	tokenFile = "token"
	// maxErrorBody caps how much of an HTTP error response we read into
	// memory. Prevents a misbehaving / malicious server from forcing the
	// CLI to allocate gigabytes by replying with a huge body.
	maxErrorBody = 64 << 10 // 64 KiB
)

var defaultAPIURL = cliResolve("ports", "backend", "28080", "http://localhost:")
var defaultFrontendURL = cliResolve("ports", "frontend_host", "23001", "http://localhost:")

// backendInDocker reports whether the vulture-backend-1 container is
// currently RUNNING. A stopped container still returns its old mount via
// `docker inspect`, which is misleading when the user has switched to
// bare-metal dev mode. When this is false, callers should treat the
// backend as a host process with full filesystem access (no path
// translation, no remount).
//
// Cached per-process: `docker inspect` shells out (~100ms cold) and the
// answer cannot change within a single CLI invocation, so we memoise.
var (
	backendInDockerOnce  sync.Once
	backendInDockerCache bool
)

func backendInDocker() bool {
	backendInDockerOnce.Do(func() {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}",
			"vulture-backend-1").Output()
		if err != nil {
			backendInDockerCache = false
			return
		}
		backendInDockerCache = strings.TrimSpace(string(out)) == "true"
	})
	return backendInDockerCache
}

// discoverSourceDir finds the host path mapped to /mnt/source in the backend
// container — but only when the container is actually running. Falls back
// to $VULTURE_SOURCE_DIR or the project .env file when no live mount is
// available. Returns "" when the backend is bare-metal (no docker mount).
func discoverSourceDir() string {
	// Primary: only trust the docker mount when the container is RUNNING.
	// A stopped container's `docker inspect` returns its stale config
	// (last mount before stop) — misleading when bare-metal dev mode took
	// over the port.
	if backendInDocker() {
		if out, err := exec.Command("docker", "inspect", "-f",
			"{{range .Mounts}}{{if eq .Destination \"/mnt/source\"}}{{.Source}}{{end}}{{end}}",
			"vulture-backend-1").Output(); err == nil {
			if src := strings.TrimSpace(string(out)); src != "" {
				return src
			}
		}
	}
	// Fallback: explicit env var
	if v := os.Getenv("VULTURE_SOURCE_DIR"); v != "" {
		return v
	}
	// Last resort: read project .env (CLI sits at <project>/cli/vulture)
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	envPath := filepath.Join(filepath.Dir(filepath.Dir(exe)), ".env")
	data, err := os.ReadFile(envPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "VULTURE_SOURCE_DIR="); ok {
			return strings.Trim(v, "\"'")
		}
	}
	return ""
}

// translateLocalPath converts a host absolute path to its container-visible
// equivalent (/mnt/source/<rel>) when the backend runs in Docker. Returns
// the original path if translation isn't possible OR if the backend is
// running bare-metal (which has full filesystem access and doesn't need
// the /mnt/source rewrite).
func translateLocalPath(hostPath, apiURL string) string {
	if !backendInDocker() {
		// Bare-metal backend: no docker mount, send the raw host path.
		return hostPath
	}
	sourceDir := discoverSourceDir()
	if sourceDir == "" {
		return hostPath
	}
	abs, err := filepath.Abs(sourceDir)
	if err != nil {
		return hostPath
	}
	rel, err := filepath.Rel(abs, hostPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return hostPath
	}
	return filepath.Join("/mnt/source", rel)
}

// pathInsideMount reports whether `target` (an absolute host path) is at or
// inside the current /mnt/source bind-mount source.
func pathInsideMount(target, mountSource string) bool {
	if mountSource == "" {
		return false
	}
	absMount, err := filepath.Abs(mountSource)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absMount, target)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// findComposeFile locates docker-compose.yml relative to the CLI binary.
// The CLI lives at <project-root>/cli/vulture, so the compose file is at
// <project-root>/docker-compose.yml.
func findComposeFile() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	for _, name := range []string{"docker-compose.yml", "compose.yml"} {
		p := filepath.Join(filepath.Dir(filepath.Dir(exe)), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// remountBackendIfNeeded ensures the backend container's /mnt/source mount
// covers `target`. If the target is already inside the current mount, this
// is a no-op. Otherwise it re-runs `docker compose up -d` with
// VULTURE_SOURCE_DIR=<target> set so the bind-mount is updated, then waits
// for the backend's /health endpoint to return 200.
//
// This solves the recurring "Error: validate path: stat <abs-path>: no such
// file or directory" surfacing when users scan paths outside the project
// root that was originally mounted.
func remountBackendIfNeeded(target, apiURL string) error {
	if !backendInDocker() {
		// Bare-metal backend: no docker bind-mount to manage; the
		// host backend can stat any path directly. No-op.
		return nil
	}
	current := discoverSourceDir()
	if current == "" {
		// Backend probably runs natively (no docker mount); nothing to remount.
		return nil
	}
	if pathInsideMount(target, current) {
		return nil
	}
	composeFile := findComposeFile()
	if composeFile == "" {
		return fmt.Errorf(
			"target %s is outside the backend mount (%s) and docker-compose.yml "+
				"could not be located to remount automatically. "+
				"Restart the stack with: VULTURE_SOURCE_DIR=%s docker compose up -d",
			target, current, target,
		)
	}
	fmt.Fprintf(os.Stderr, "  Source %s is outside the current backend mount (%s).\n", target, current)
	fmt.Fprintf(os.Stderr, "  Remounting backend to %s ... (Ctrl+C to abort)\n", target)

	composeDir := filepath.Dir(composeFile)
	cmd := exec.Command("docker", "compose", "-f", composeFile, "up", "-d")
	cmd.Env = append(os.Environ(), "VULTURE_SOURCE_DIR="+target)
	cmd.Dir = composeDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}
	// Wait for /health.
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(apiURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(os.Stderr, "  Backend healthy. Mount is now %s -> /mnt/source.\n", target)
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("backend did not become healthy within 120s after remount")
}

type authResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	} `json:"user"`
}

type source struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Path      string `json:"path"`
	FileCount int    `json:"file_count"`
}

type audit struct {
	ID            string         `json:"id"`
	SourceID      string         `json:"source_id"`
	SourcePath    string         `json:"source_path"`
	Status        string         `json:"status"`
	Types         []string       `json:"types"`
	Findings      []finding      `json:"findings"`
	FindingsCount int            `json:"findings_count"`
	Scores        map[string]int `json:"scores"`
	CreatedAt     string         `json:"created_at"`
	CompletedAt   string         `json:"completed_at"`
}

type finding struct {
	ID             string `json:"id"`
	AgentType      string `json:"agent_type"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	FilePath       string `json:"file_path"`
	LineStart      int    `json:"line_start"`
	Recommendation string `json:"recommendation"`
	Fingerprint    string `json:"fingerprint"`
	Ref            string `json:"ref,omitempty"`
}

type lineageRec struct {
	Fingerprint string `json:"fingerprint"`
	Ref         string `json:"ref"`
	RefNumber   int    `json:"ref_number"`
}

type cacheResponse struct {
	Cached bool  `json:"cached"`
	Audit  audit `json:"audit"`
}

// ciFlags holds flags shared by scan and prove for CI/CD integration.
type ciFlags struct {
	apiKey         string // --api-key: overrides stored JWT
	server         string // --server: overrides defaultAPIURL
	wait           bool   // --wait: block until audit completes
	output         string // --output: "text" or "json"
	exitOn         string // --exit-on: exit non-zero at/above severity
	webhook        string // --webhook: POST completion notification URL
	ref            string // --ref: git ref (branch/tag/SHA)
	gitCredentials string // --git-credentials: "token:VALUE" or "ssh_key:VALUE"
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	apiURL := os.Getenv("VULTURE_API_URL")
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	cmd := os.Args[1]
	switch cmd {
	case "login":
		cmdLogin(apiURL)
	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: vulture scan <path-or-git-url> [--types %s] [--no-cache] [CI flags]\n", strings.Join(agentregistry.ScanAgentTypes(), ","))
			os.Exit(1)
		}
		types, noCache, ci := parseScanFlags(os.Args[3:])
		if ci.server != "" {
			apiURL = ci.server
		}
		cmdScan(apiURL, os.Args[2], types, noCache, ci)
	case "discover", "discovery":
		df := parseDiscoverFlags(os.Args[2:])
		cmdDiscover(apiURL, df)
	case "prove":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: vulture prove <path-or-url> --staging-url <url> [--types %s] [--max-iterations 3] [--allow-local] [--no-cache] [CI flags]\n", strings.Join(agentregistry.ScanAgentTypes(), ","))
			os.Exit(1)
		}
		pf := parseProveFlags(os.Args[3:])
		if pf.ci.server != "" {
			apiURL = pf.ci.server
		}
		cmdProve(apiURL, os.Args[2], pf)
	case "api-key":
		cmdAPIKey(apiURL, os.Args[2:])
	case "localstart", "local-start", "local_start":
		cmdLocalStart()
	case "localstop", "local-stop", "local_stop":
		cmdLocalStop()
	case "status":
		cmdStatus(apiURL)
	case "results":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: vulture results <audit-id>")
			os.Exit(1)
		}
		cmdResults(apiURL, os.Args[2])
	case "help", "--help", "-h":
		printUsage()
	default:
		if !looksLikePath(cmd) {
			fmt.Fprintf(os.Stderr, "  Error: unknown command %q\n\n", cmd)
			printUsage()
			os.Exit(1)
		}
		types, noCache, ci := parseScanFlags(os.Args[2:])
		if ci.server != "" {
			apiURL = ci.server
		}
		cmdScan(apiURL, cmd, types, noCache, ci)
	}
}

// parseScanFlags extracts --types, --no-cache, and CI flags from arguments.
func parseScanFlags(args []string) (types []string, noCache bool, ci ciFlags) {
	types = agentregistry.ScanAgentTypes()
	ci.output = "text"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--types":
			if i+1 < len(args) {
				types = strings.Split(args[i+1], ",")
				i++
			}
		case "--no-cache":
			noCache = true
		default:
			if consumed := parseCIFlag(args, i, &ci); consumed > 0 {
				i += consumed - 1
			}
		}
	}
	return
}

// parseCIFlag parses a single CI flag at position i. Returns the number of
// args consumed (0 if not a CI flag, 1 for bool flags, 2 for value flags).
func parseCIFlag(args []string, i int, ci *ciFlags) int {
	switch args[i] {
	case "--api-key":
		if i+1 < len(args) {
			ci.apiKey = args[i+1]
			return 2
		}
	case "--server":
		if i+1 < len(args) {
			ci.server = args[i+1]
			return 2
		}
	case "--wait":
		ci.wait = true
		return 1
	case "--output":
		if i+1 < len(args) {
			ci.output = args[i+1]
			return 2
		}
	case "--exit-on":
		if i+1 < len(args) {
			ci.exitOn = args[i+1]
			return 2
		}
	case "--webhook":
		if i+1 < len(args) {
			ci.webhook = args[i+1]
			return 2
		}
	case "--ref":
		if i+1 < len(args) {
			ci.ref = args[i+1]
			return 2
		}
	case "--git-credentials":
		if i+1 < len(args) {
			ci.gitCredentials = args[i+1]
			return 2
		}
	}
	return 0
}

func printUsage() {
	scanTypes := strings.Join(agentregistry.ScanAgentTypes(), ",")
	fmt.Printf(`Vulture CLI - Compliance Audit Platform

Usage:
  vulture login                          Authenticate with the Vulture server
  vulture scan <path-or-url> [--types]   Scan source code for compliance issues
  vulture discover [path] [flags]        Discover endpoints and attack surface
  vulture prove <path-or-url> [flags]    Verify findings against a staging environment
  vulture api-key <create|list|revoke>   Manage API keys for CI/CD authentication
  vulture <path-or-url>                  Shorthand for scan
  vulture localstart                     Start all services locally (backend + agents + frontend)
  vulture localstop                      Stop all locally running services
  vulture status                         Show recent audit statuses
  vulture results <audit-id>             Show detailed results for an audit

Scan Options:
  --types %s  Comma-separated audit types (default: all)
  --no-cache                        Force fresh audit, skip cached results

Discover Options:
  --target-url <url>                Target URL to discover (required)
  --no-cache                        Skip previously reported items, look for new ones
  --rate-limit <seconds>            Delay between HTTP requests (default: 0 = no limit)

Prove Options:
  --staging-url <url>               Staging environment URL (required)
  --types %s  Scanner types to verify (default: all)
  --max-iterations <n>          Max verification attempts per finding (default: 3, max: 65535)
  --allow-local                 Allow targeting localhost/local IPs
  --no-cache                    Force fresh scan, skip cached findings

CI/CD Flags (scan, prove):
  --api-key <key>               API key for machine auth (overrides stored JWT)
  --server <url>                Server URL (overrides VULTURE_API_URL / config.ini)
  --wait                        Block until audit completes; print result
  --output <text|json>          Output format (default: text)
  --exit-on <severity>          Exit non-zero if findings at/above severity
                                (critical, high, medium, low)
  --webhook <url>               POST completion notification to this URL
  --ref <ref>                   Git ref (branch/tag/SHA) for git URL sources
  --git-credentials <creds>     Git credentials (format: token:VALUE or ssh_key:VALUE)

API Key Management:
  vulture api-key create <name>     Create a new API key
  vulture api-key list              List active API keys
  vulture api-key revoke <id>       Revoke an API key

Environment:
  VULTURE_API_URL             API server URL (default: from config.ini [ports] backend)

Examples:
  vulture login
  vulture scan /path/to/project
  vulture scan https://github.com/org/repo.git --types owasp,soc2,cwe
  vulture scan https://github.com/org/repo.git --api-key vk_abc123 --wait --exit-on high
  vulture scan https://github.com/org/repo.git --server https://vulture.example.com --output json
  vulture discover --target-url https://staging.example.com
  vulture discover /path/to/project --target-url https://staging.example.com
  vulture prove /path/to/project --staging-url https://staging.example.com --types owasp
  vulture api-key create ci-github-actions
  vulture api-key list
  vulture api-key revoke <key-id>
  vulture localstart
  vulture /path/to/project
  vulture status
  vulture results abc123
`, scanTypes, scanTypes)
}

type discoverFlags struct {
	targetURL  string
	sourcePath string
	noCache    bool
	rateLimit  float64
}

func parseDiscoverFlags(args []string) discoverFlags {
	df := discoverFlags{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target-url", "--staging-url":
			if i+1 < len(args) {
				df.targetURL = args[i+1]
				i++
			}
		case "--no-cache":
			df.noCache = true
		case "--rate-limit":
			if i+1 < len(args) {
				if v, err := strconv.ParseFloat(args[i+1], 64); err == nil && v >= 0 {
					df.rateLimit = v
				}
				i++
			}
		default:
			// Positional arg = source path
			if !strings.HasPrefix(args[i], "--") && df.sourcePath == "" {
				df.sourcePath = args[i]
			}
		}
	}
	return df
}

func cmdDiscover(apiURL string, df discoverFlags) {
	if df.targetURL == "" {
		fatalf("--target-url is required for discover command")
	}

	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}

	var sourceID string

	// Create source if path provided (triggers scan → discover pipeline)
	if df.sourcePath != "" {
		srcType := "local"
		target := df.sourcePath
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasSuffix(target, ".git") {
			srcType = "git"
		}
		if srcType == "local" {
			abs, err := filepath.Abs(target)
			if err == nil {
				target = abs
			}
			if err := remountBackendIfNeeded(target, apiURL); err != nil {
				fatalf("remount backend: %v", err)
			}
			target = translateLocalPath(target, apiURL)
		}

		fmt.Printf("  Submitting source (%s): %s\n", srcType, target)
		srcBody := map[string]string{"type": srcType}
		if srcType == "git" {
			srcBody["url"] = target
		} else {
			srcBody["path"] = target
		}
		srcJSON, _ := json.Marshal(srcBody)
		src := apiPost[source](apiURL+"/api/sources", srcJSON, token)
		sourceID = src.ID
		fmt.Printf("  Source created: %s (%d files)\n", truncateID(src.ID, 12), src.FileCount)
	}

	fmt.Printf("  Target URL: %s\n", df.targetURL)

	// Create discover audit
	discoverCfg := map[string]interface{}{
		"target_url": df.targetURL,
		"no_cache":   df.noCache,
	}
	if df.rateLimit > 0 {
		discoverCfg["rate_limit"] = df.rateLimit
		fmt.Printf("  Rate limit: %.1fs between requests\n", df.rateLimit)
	}
	cfg := map[string]interface{}{
		"discover": discoverCfg,
	}

	auditReq := map[string]interface{}{
		"types":  []string{"discover"},
		"config": cfg,
	}
	if sourceID != "" {
		auditReq["source_id"] = sourceID
	}

	auditBody, _ := json.Marshal(auditReq)
	a := apiPost[audit](apiURL+"/api/audits", auditBody, token)
	fmt.Printf("  Discover session: %s\n\n", truncateID(a.ID, 12))

	// Stream discover results
	fmt.Println(strings.Repeat("-", 60))
	streamDiscover(apiURL, a.ID, token)
	fmt.Println(strings.Repeat("-", 60))

	// Fetch final results
	final := apiGet[audit](apiURL+"/api/audits/"+a.ID, token)
	printAuditSummary(final)
}

func streamDiscover(apiURL, auditID, token string) {
	url := apiURL + "/api/audits/" + auditID + "/stream"
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		fatalf("Stream connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		fatalf("Stream error (%d): %s", resp.StatusCode, string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var eventType string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			printDiscoverEvent(eventType, data)
		}
	}
}

func printDiscoverEvent(eventType, data string) {
	var evt map[string]interface{}
	json.Unmarshal([]byte(data), &evt)

	switch eventType {
	case "RunStarted":
		fmt.Println("  Discovery started")
	case "StepStarted":
		printEvtField(evt, "stepName", "\n  \033[34m>>> %s\033[0m\n")
	case "TextMessageContent":
		printDelta(evt)
	case "StateDelta":
		printDiscoverDelta(evt)
	case "StateSnapshot":
		printStateSnapshot(evt)
	case "StepFinished":
		printEvtField(evt, "stepName", "  \033[32m<<< %s done\033[0m\n")
	case "RunFinished":
		fmt.Println("\n  \033[32mDiscovery completed\033[0m")
	case "RunError":
		printEvtField(evt, "error", "  \033[31mERROR: %s\033[0m\n")
	}
}

func printDiscoverDelta(evt map[string]interface{}) {
	delta, ok := evt["delta"]
	if !ok {
		return
	}

	// JSON-patch array → finding patches
	if arr, ok := delta.([]interface{}); ok {
		for _, patch := range arr {
			printFindingPatch(patch)
		}
		return
	}

	m, ok := delta.(map[string]interface{})
	if !ok {
		return
	}

	// Discover result with SiteMap data
	if dr, ok := m["discover_result"].(map[string]interface{}); ok {
		urlCount, _ := dr["url_count"].(float64)
		apiCount, _ := dr["api_count"].(float64)
		formCount, _ := dr["form_count"].(float64)
		targetURL, _ := dr["target_url"].(string)

		fmt.Printf("\n  \033[34mDiscovery Results for %s\033[0m\n", targetURL)
		fmt.Printf("    URLs discovered:     %d\n", int(urlCount))
		fmt.Printf("    API endpoints:       %d\n", int(apiCount))
		fmt.Printf("    Forms:               %d\n", int(formCount))

		if techs, ok := dr["technologies"].([]interface{}); ok && len(techs) > 0 {
			techStrs := make([]string, len(techs))
			for i, t := range techs {
				techStrs[i], _ = t.(string)
			}
			fmt.Printf("    Technologies:        %s\n", strings.Join(techStrs, ", "))
		}
	}

	// Token savings and dedup (reuse existing helpers)
	if ts, ok := m["token_savings"].(map[string]interface{}); ok {
		printTokenSavings(ts)
	}
	if ds, ok := m["dedup_stats"].(map[string]interface{}); ok {
		printDedupStats(ds)
	}
}

type proveFlags struct {
	stagingURL    string
	types         []string
	maxIterations int
	allowLocal    bool
	noCache       bool
	ci            ciFlags
}

func parseProveFlags(args []string) proveFlags {
	pf := proveFlags{
		types:         agentregistry.ScanAgentTypes(),
		maxIterations: 3,
	}
	pf.ci.output = "text"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--staging-url":
			if i+1 < len(args) {
				pf.stagingURL = args[i+1]
				i++
			}
		case "--types":
			if i+1 < len(args) {
				pf.types = strings.Split(args[i+1], ",")
				i++
			}
		case "--max-iterations":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					if n < 1 {
						n = 1
					}
					if n > 65535 {
						n = 65535
					}
					pf.maxIterations = n
				}
				i++
			}
		case "--allow-local":
			pf.allowLocal = true
		case "--no-cache":
			pf.noCache = true
		default:
			if consumed := parseCIFlag(args, i, &pf.ci); consumed > 0 {
				i += consumed - 1
			}
		}
	}
	return pf
}

// --- Commands ---

func cmdLocalStart() {
	root := findProjectRoot()
	bin := filepath.Join(root, "backend", "vulture")
	if _, err := os.Stat(bin); err != nil {
		fatalf("Backend binary not found at %s\n  Build it first: cd %s/backend && go build -o vulture ./cmd/vulture/", bin, root)
	}

	binAbs, err := filepath.Abs(bin)
	if err != nil {
		fatalf("resolve path: %v", err)
	}

	// exec replaces the current process with the backend binary
	args := []string{binAbs, "local_start"}
	if execErr := syscall.Exec(binAbs, args, os.Environ()); execErr != nil {
		fatalf("exec backend: %v", execErr)
	}
}

var localServices = buildLocalServices()

func buildLocalServices() []struct {
	name string
	port string
} {
	services := make([]struct {
		name string
		port string
	}, 0, len(agentregistry.AllAgents)+2)
	services = append(services, struct {
		name string
		port string
	}{"backend", cliINIValue("ports", "backend", "28080")})
	for _, entry := range agentregistry.AllAgents {
		services = append(services, struct {
			name string
			port string
		}{"agent-" + entry.Type, cliINIValue("ports", entry.INIKey, entry.DefaultPort)})
	}
	services = append(services, struct {
		name string
		port string
	}{"frontend", cliINIValue("ports", "frontend_host", "23001")})
	return services
}

func cmdLocalStop() {
	fmt.Println("  Stopping Vulture services...")
	stopped := 0

	for _, svc := range localServices {
		pids := findPIDsOnPort(svc.port)
		if len(pids) == 0 {
			continue
		}
		for _, pid := range pids {
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: kill %s (pid %d): %v\n", svc.name, pid, err)
				continue
			}
			fmt.Printf("  Stopped %-15s (pid %d, port %s)\n", svc.name, pid, svc.port)
			stopped++
		}
	}

	if stopped == 0 {
		fmt.Println("  No running Vulture services found.")
		return
	}

	// Wait briefly for processes to exit
	time.Sleep(500 * time.Millisecond)

	// Verify ports are free
	remaining := 0
	for _, svc := range localServices {
		if isPortOpen(svc.port) {
			remaining++
		}
	}
	if remaining > 0 {
		fmt.Printf("\n  %d service(s) still shutting down, sending SIGKILL...\n", remaining)
		for _, svc := range localServices {
			for _, pid := range findPIDsOnPort(svc.port) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}

	fmt.Printf("\n  %d service(s) stopped.\n", stopped)
}

// findPIDsOnPort uses lsof to find process IDs listening on a port.
func findPIDsOnPort(port string) []int {
	out, err := exec.Command("lsof", "-ti", ":"+port).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// isPortOpen checks if something is still listening on the given port.
func isPortOpen(port string) bool {
	conn, err := net.DialTimeout("tcp", "localhost:"+port, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func findProjectRoot() string {
	// 1. Check relative to the CLI binary itself
	self, err := os.Executable()
	if err == nil {
		selfDir := filepath.Dir(self)
		for _, rel := range []string{"..", "../.."} {
			candidate, _ := filepath.Abs(filepath.Join(selfDir, rel))
			if isProjectRoot(candidate) {
				return candidate
			}
		}
	}

	// 2. Check relative to cwd
	cwd, _ := os.Getwd()
	for _, rel := range []string{".", "..", "../.."} {
		candidate, _ := filepath.Abs(filepath.Join(cwd, rel))
		if isProjectRoot(candidate) {
			return candidate
		}
	}

	fatalf("Could not find Vulture project root (looking for docker-compose.yml + backend/).\n  Run this command from inside the vulture project directory.")
	return ""
}

// looksLikePath returns true if the argument looks like a file path or URL
// rather than a mistyped command name.
func looksLikePath(arg string) bool {
	if strings.ContainsAny(arg, "/\\") {
		return true
	}
	if strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "~") {
		return true
	}
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return true
	}
	if strings.HasSuffix(arg, ".git") {
		return true
	}
	// Check if it's an existing file or directory
	if _, err := os.Stat(arg); err == nil {
		return true
	}
	return false
}

func isLocalMode(frontendURL string) bool {
	if os.Getenv("VULTURE_LOCAL_MODE") == "false" {
		return false
	}
	return strings.Contains(frontendURL, "localhost") || strings.Contains(frontendURL, "127.0.0.1")
}

func isProjectRoot(dir string) bool {
	if fi, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil || fi.IsDir() {
		return false
	}
	if fi, err := os.Stat(filepath.Join(dir, "backend")); err != nil || !fi.IsDir() {
		return false
	}
	return true
}

func autoLoginLocal(apiURL string) string {
	body, _ := json.Marshal(map[string]string{
		"email":    "admin@vulture.local",
		"password": "REDACTED-DEV-PW",
	})
	resp, err := http.Post(apiURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var auth authResponse
	json.NewDecoder(resp.Body).Decode(&auth)
	if auth.Token != "" {
		saveToken(auth.Token)
	}
	return auth.Token
}

func cmdLogin(apiURL string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Password: ")
	var password string
	if term.IsTerminal(int(syscall.Stdin)) {
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fatalf("Failed to read password: %v", err)
		}
		password = string(passwordBytes)
	} else {
		password, _ = reader.ReadString('\n')
		password = strings.TrimSpace(password)
	}

	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(apiURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fatalf("Connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			fatalf("Login failed: %s", errResp.Error)
		}
		fatalf("Login failed (status %d). Check your credentials.", resp.StatusCode)
	}

	var auth authResponse
	json.NewDecoder(resp.Body).Decode(&auth)

	saveToken(auth.Token)
	fmt.Printf("\n  Logged in as %s (%s)\n  Token saved to ~/%s/%s\n\n", auth.User.Name, auth.User.Email, configDir, tokenFile)
}

func cmdScan(apiURL string, target string, types []string, noCache bool, ci ciFlags) {
	token := resolveToken(ci.apiKey, apiURL)

	// Determine source type
	srcType := "local"
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasSuffix(target, ".git") {
		srcType = "git"
	}

	// Resolve local path to absolute
	if srcType == "local" {
		abs, err := filepath.Abs(target)
		if err == nil {
			target = abs
		}
		if err := remountBackendIfNeeded(target, apiURL); err != nil {
			fatalf("remount backend: %v", err)
		}
		target = translateLocalPath(target, apiURL)
	}

	fmt.Fprintf(os.Stderr, "  Submitting source (%s): %s\n", srcType, target)

	// Create source
	srcBody := buildSourceBody(srcType, target, ci)
	srcJSON, _ := json.Marshal(srcBody)
	src := apiPost[source](apiURL+"/api/sources", srcJSON, token)
	fmt.Fprintf(os.Stderr, "  Source created: %s (%d files)\n", truncateID(src.ID, 12), src.FileCount)

	// Check for cached results
	if !noCache {
		cacheURL := fmt.Sprintf("%s/api/audits/cache?source_id=%s&types=%s", apiURL, src.ID, strings.Join(types, ","))
		cached := apiGet[cacheResponse](cacheURL, token)
		if cached.Cached && cached.Audit.ID != "" {
			fmt.Fprintf(os.Stderr, "\n  \033[33m⚡ Cached results found (audit %s)\033[0m\n", truncateID(cached.Audit.ID, 12))
			fmt.Fprintf(os.Stderr, "  Completed: %s\n", cached.Audit.CompletedAt)
			fmt.Fprintf(os.Stderr, "  Use --no-cache to force a fresh audit\n")
			fmt.Fprintln(os.Stderr, strings.Repeat("-", 60))
			outputResult(cached.Audit, ci)
			os.Exit(computeExitCode(cached.Audit, ci.exitOn))
		}
	}

	// Create audit
	auditReq := buildAuditBody(src.ID, types, ci)
	auditBody, _ := json.Marshal(auditReq)
	a := apiPost[audit](apiURL+"/api/audits", auditBody, token)
	fmt.Fprintf(os.Stderr, "  Audit started: %s\n", truncateID(a.ID, 12))
	fmt.Fprintf(os.Stderr, "  Types: %s\n\n", joinAgentNames(types))

	if ci.wait {
		fmt.Fprintf(os.Stderr, "  Waiting for audit to complete...\n")
		final := pollUntilDone(apiURL, a.ID, token)
		outputResult(final, ci)
		os.Exit(computeExitCode(final, ci.exitOn))
	}

	// Stream results
	fmt.Fprintln(os.Stderr, "  Streaming results...")
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 60))
	streamAudit(apiURL, a.ID, token)

	// Fetch final results
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 60))
	final := apiGet[audit](apiURL+"/api/audits/"+a.ID, token)
	outputResult(final, ci)
	os.Exit(computeExitCode(final, ci.exitOn))
}

func cmdProve(apiURL string, target string, pf proveFlags) {
	if pf.stagingURL == "" {
		fatalf("--staging-url is required for prove command")
	}

	token := resolveToken(pf.ci.apiKey, apiURL)

	// Determine source type
	srcType := "local"
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasSuffix(target, ".git") {
		srcType = "git"
	}

	if srcType == "local" {
		abs, err := filepath.Abs(target)
		if err == nil {
			target = abs
		}
		if err := remountBackendIfNeeded(target, apiURL); err != nil {
			fatalf("remount backend: %v", err)
		}
		target = translateLocalPath(target, apiURL)
	}

	fmt.Fprintf(os.Stderr, "  Submitting source (%s): %s\n", srcType, target)

	srcBody := buildSourceBody(srcType, target, pf.ci)
	srcJSON, _ := json.Marshal(srcBody)
	src := apiPost[source](apiURL+"/api/sources", srcJSON, token)
	fmt.Fprintf(os.Stderr, "  Source created: %s (%d files)\n", truncateID(src.ID, 12), src.FileCount)

	// Step 1: Get scanner findings (from cache, fresh scan, or memory)
	findings := proveGetFindings(apiURL, src.ID, target, pf.types, token, pf.noCache)
	if len(findings) == 0 {
		fmt.Println("\n  No findings to verify. The scan produced no results.")
		return
	}
	fmt.Printf("\n  \033[34m%d findings to verify against %s\033[0m\n", len(findings), pf.stagingURL)

	// Step 2: Convert findings for the prove agent config
	findingMaps := make([]map[string]interface{}, len(findings))
	for i, f := range findings {
		findingMaps[i] = map[string]interface{}{
			"id":             f.ID,
			"agent_type":     f.AgentType,
			"severity":       f.Severity,
			"category":       f.Category,
			"title":          f.Title,
			"description":    truncateStr(f.Description, 500),
			"file_path":      f.FilePath,
			"line_start":     f.LineStart,
			"recommendation": truncateStr(f.Recommendation, 300),
		}
	}

	// Step 3: Create prove audit with findings embedded in config
	// Config is nested under "prove" key because extractAgentConfig looks for config[agentType]
	auditReq := map[string]interface{}{
		"source_id": src.ID,
		"types":     []string{"prove"},
		"config": map[string]interface{}{
			"prove": map[string]interface{}{
				"staging_url":    pf.stagingURL,
				"types":          pf.types,
				"max_iterations": pf.maxIterations,
				"allow_local":    pf.allowLocal,
				"findings":       findingMaps,
			},
		},
	}
	if pf.ci.webhook != "" {
		auditReq["webhook_url"] = pf.ci.webhook
	}
	auditBody, _ := json.Marshal(auditReq)
	a := apiPost[audit](apiURL+"/api/audits", auditBody, token)
	fmt.Fprintf(os.Stderr, "  Prove session: %s\n", truncateID(a.ID, 12))
	fmt.Fprintf(os.Stderr, "  Max iterations: %d\n\n", pf.maxIterations)

	if pf.ci.wait {
		fmt.Fprintf(os.Stderr, "  Waiting for prove session to complete...\n")
		final := pollUntilDone(apiURL, a.ID, token)
		outputResult(final, pf.ci)
		os.Exit(computeExitCode(final, pf.ci.exitOn))
	}

	// Step 4: Stream verification results
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 60))
	streamProve(apiURL, a.ID, token)
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 60))

	// Fetch final results for exit code evaluation
	final := apiGet[audit](apiURL+"/api/audits/"+a.ID, token)
	outputResult(final, pf.ci)
	os.Exit(computeExitCode(final, pf.ci.exitOn))
}

// proveGetFindings runs a scan (or uses cache) and returns the findings.
func proveGetFindings(apiURL, sourceID, sourcePath string, types []string, token string, noCache bool) []finding {
	// Check cache first (unless --no-cache)
	if !noCache {
		cacheURL := fmt.Sprintf("%s/api/audits/cache?source_id=%s&types=%s", apiURL, sourceID, strings.Join(types, ","))
		cached := apiGet[cacheResponse](cacheURL, token)
		if cached.Cached && cached.Audit.ID != "" && len(cached.Audit.Findings) > 0 {
			fmt.Printf("\n  \033[33m⚡ Using cached scan results (audit %s, %d findings)\033[0m\n",
				truncateID(cached.Audit.ID, 12), len(cached.Audit.Findings))
			return cached.Audit.Findings
		}
	}

	// No cache — run a fresh scan
	fmt.Printf("\n  Running scan first (%s)...\n", joinAgentNames(types))
	auditBody, _ := json.Marshal(map[string]interface{}{
		"source_id": sourceID,
		"types":     types,
	})
	a := apiPost[audit](apiURL+"/api/audits", auditBody, token)
	fmt.Printf("  Scan started: %s\n", truncateID(a.ID, 12))

	// Stream scan progress
	streamAudit(apiURL, a.ID, token)

	// Fetch final results with findings
	final := apiGet[audit](apiURL+"/api/audits/"+a.ID, token)
	if len(final.Findings) > 0 {
		fmt.Printf("  Scan complete: %d findings\n", final.findingCount())
		return final.Findings
	}

	// Scan produced no findings — check memory system for prior findings
	return proveGetMemoryFindings(apiURL, sourcePath, types, token)
}

func proveGetMemoryFindings(apiURL, sourcePath string, types []string, token string) []finding {
	memURL := fmt.Sprintf("%s/api/memories/by-path?path=%s&limit=100", apiURL, sourcePath)
	req, err := http.NewRequest("GET", memURL, nil)
	if err != nil {
		return nil
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	var memories []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&memories); err != nil {
		return nil
	}
	typeSet := make(map[string]bool, len(types))
	for _, t := range types {
		typeSet[t] = true
	}
	// Deduplicate by title+agent_type
	seen := make(map[string]bool)
	var results []finding
	for _, m := range memories {
		agentType, _ := m["agent_type"].(string)
		if !typeSet[agentType] {
			continue
		}
		title, _ := m["title"].(string)
		key := agentType + ":" + title
		if seen[key] {
			continue
		}
		seen[key] = true
		id, _ := m["id"].(string)
		sev, _ := m["severity"].(string)
		cat, _ := m["category"].(string)
		desc, _ := m["content"].(string)
		results = append(results, finding{
			ID:          id,
			AgentType:   agentType,
			Severity:    sev,
			Category:    cat,
			Title:       title,
			Description: desc,
		})
	}
	if len(results) > 0 {
		fmt.Printf("  Scan produced no new findings; loaded %d prior findings from memory\n", len(results))
	} else {
		fmt.Println("  Scan complete: 0 findings")
	}
	return results
}

func streamProve(apiURL, auditID, token string) {
	url := apiURL + "/api/audits/" + auditID + "/stream"
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		fatalf("Stream connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		fatalf("Stream error (%d): %s", resp.StatusCode, string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var eventType string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			printProveEvent(eventType, data)
		}
	}
}

func printProveEvent(eventType, data string) {
	var evt map[string]interface{}
	json.Unmarshal([]byte(data), &evt)

	switch eventType {
	case "RunStarted":
		fmt.Println("  Prove session started")
	case "StepStarted":
		printEvtField(evt, "stepName", "\n  \033[34m>>> %s\033[0m\n")
	case "TextMessageContent":
		printDelta(evt)
	case "StateDelta":
		printProveDelta(evt)
	case "StepFinished":
		printEvtField(evt, "stepName", "  \033[32m<<< %s done\033[0m\n")
	case "RunFinished":
		fmt.Println("\n  \033[32mProve session completed\033[0m")
	case "RunError":
		printEvtField(evt, "error", "  \033[31mERROR: %s\033[0m\n")
	}
}

func printProveDelta(evt map[string]interface{}) {
	delta, ok := evt["delta"]
	if !ok {
		return
	}
	m, ok := delta.(map[string]interface{})
	if !ok {
		return
	}

	if plan, ok := m["proof_plan"].(map[string]interface{}); ok {
		title, _ := plan["title"].(string)
		planText, _ := plan["plan_text"].(string)
		iter, _ := plan["iteration"].(float64)
		fmt.Printf("  [%s]\n", title)
		fmt.Printf("    Plan (attempt %d): %s\n", int(iter), planText)
	}

	if review, ok := m["proof_review"].(map[string]interface{}); ok {
		safe, _ := review["safe"].(bool)
		if safe {
			fmt.Printf("    Review: \033[32mSAFE\033[0m\n")
		} else {
			fmt.Printf("    Review: \033[31mUNSAFE\033[0m — skipping\n")
		}
	}

	if attempt, ok := m["proof_attempt"].(map[string]interface{}); ok {
		reproduced, _ := attempt["reproduced"].(bool)
		evidence, _ := attempt["evidence"].(string)
		iter, _ := attempt["iteration"].(float64)
		if reproduced {
			fmt.Printf("    Attempt %d: %s \033[31m→ REPRODUCED\033[0m\n", int(iter), evidence)
		} else {
			fmt.Printf("    Attempt %d: %s → inconclusive\n", int(iter), evidence)
		}
	}

	if refl, ok := m["proof_reflection"].(map[string]interface{}); ok {
		analysis, _ := refl["analysis"].(string)
		approach, _ := refl["suggested_approach"].(string)
		confidence, _ := refl["confidence"].(float64)
		fmt.Printf("    \033[36mReflection (confidence %d%%)\033[0m: %s\n", int(confidence), analysis)
		fmt.Printf("    \033[36mNext approach\033[0m: %s\n", approach)
	}

	if result, ok := m["proof_result"].(map[string]interface{}); ok {
		status, _ := result["status"].(string)
		evidence, _ := result["evidence"].(string)
		switch status {
		case "verified":
			fmt.Printf("    Result: \033[31mVERIFIED\033[0m — %s\n", evidence)
		case "not_reproduced":
			fmt.Printf("    Result: \033[32mNOT REPRODUCED\033[0m — %s\n", evidence)
		case "skipped":
			fmt.Printf("    Result: \033[33mSKIPPED\033[0m — %s\n", evidence)
		default:
			fmt.Printf("    Result: \033[33mINCONCLUSIVE\033[0m — %s\n", evidence)
		}
	}

	if summary, ok := m["proof_summary"].(map[string]interface{}); ok {
		total, _ := summary["total"].(float64)
		verified, _ := summary["verified"].(float64)
		notRepr, _ := summary["not_reproduced"].(float64)
		inconc, _ := summary["inconclusive"].(float64)
		skipped, _ := summary["skipped"].(float64)
		fmt.Printf("\n  Summary: %d findings tested, \033[31m%d verified\033[0m, \033[32m%d not reproduced\033[0m, %d inconclusive, %d skipped\n",
			int(total), int(verified), int(notRepr), int(inconc), int(skipped))
	}
}

func cmdStatus(apiURL string) {
	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}
	audits := apiGet[[]audit](apiURL+"/api/audits?limit=10", token)

	if len(audits) == 0 {
		fmt.Println("  No audits found.")
		return
	}

	fmt.Println()
	fmt.Printf("  %-14s %-12s %-20s %-10s %s\n", "AUDIT ID", "STATUS", "TYPES", "FINDINGS", "DATE")
	fmt.Println("  " + strings.Repeat("-", 70))
	for _, a := range audits {
		findCount := a.findingCount()
		status := colorStatus(a.Status)
		date := ""
		if t, err := time.Parse(time.RFC3339Nano, a.CreatedAt); err == nil {
			date = t.Format("2006-01-02 15:04")
		}
		idDisplay := a.ID
		if len(idDisplay) > 12 {
			idDisplay = idDisplay[:12] + "..."
		}
		fmt.Printf("  %-14s %-12s %-20s %-10d %s\n",
			idDisplay,
			status,
			joinAgentNames(a.Types),
			findCount,
			date,
		)
	}
	fmt.Println()
}

// fetchRefsBySourcePath returns a fingerprint→VLT-ref map for the given source path.
// Returns nil on any error (non-fatal — CLI falls back to no refs).
func fetchRefsBySourcePath(apiURL, token, sourcePath string) map[string]string {
	if sourcePath == "" {
		return nil
	}
	u := apiURL + "/api/lineage?source_path=" + url.QueryEscape(sourcePath) + "&limit=10000"
	recs := apiGet[[]lineageRec](u, token)
	if len(recs) == 0 {
		return nil
	}
	m := make(map[string]string, len(recs))
	for _, r := range recs {
		if r.Ref != "" && r.Fingerprint != "" {
			m[r.Fingerprint] = r.Ref
		}
	}
	return m
}

func cmdResults(apiURL string, id string) {
	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}
	a := apiGet[audit](apiURL+"/api/audits/"+id, token)
	printAuditSummary(a)

	if len(a.Findings) == 0 {
		return
	}

	refs := fetchRefsBySourcePath(apiURL, token, a.SourcePath)

	fmt.Println("\n  FINDINGS:")
	fmt.Println("  " + strings.Repeat("-", 70))
	for i, f := range a.Findings {
		ref := f.Ref
		if ref == "" {
			ref = refs[f.Fingerprint]
		}
		sev := colorSeverity(f.Severity)
		if ref != "" {
			fmt.Printf("  %d. %s [%s] %s\n", i+1, ref, sev, f.Title)
		} else {
			fmt.Printf("  %d. [%s] %s\n", i+1, sev, f.Title)
		}
		fmt.Printf("     File: %s:%d\n", f.FilePath, f.LineStart)
		fmt.Printf("     Category: %s | Agent: %s\n", f.Category, agentDisplayName(f.AgentType))
		if f.Recommendation != "" {
			fmt.Printf("     Fix: %s\n", f.Recommendation)
		}
		fmt.Println()
	}
}

// --- CI/CD helpers ---

// resolveToken returns the appropriate auth token. If an API key is provided,
// it is used directly. Otherwise falls back to stored JWT or local auto-login.
func resolveToken(apiKey, apiURL string) string {
	if apiKey != "" {
		return apiKey
	}
	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}
	return token
}

// buildSourceBody constructs the JSON body for POST /api/sources, including
// optional git ref and credentials from CI flags.
func buildSourceBody(srcType, target string, ci ciFlags) map[string]interface{} {
	body := map[string]interface{}{"type": srcType}
	if srcType == "git" {
		body["url"] = target
		if ci.ref != "" {
			body["ref"] = ci.ref
		}
		if ci.gitCredentials != "" {
			credType, credValue := parseGitCredentials(ci.gitCredentials)
			if credType != "" {
				body["git_credentials"] = map[string]string{
					"type":  credType,
					"value": credValue,
				}
			}
		}
	} else {
		body["path"] = target
	}
	return body
}

// parseGitCredentials splits "type:value" into its parts.
// Accepted types: "token", "ssh_key".
func parseGitCredentials(creds string) (string, string) {
	idx := strings.Index(creds, ":")
	if idx < 1 {
		fmt.Fprintf(os.Stderr, "  Warning: invalid --git-credentials format (expected type:value)\n")
		return "", ""
	}
	credType := creds[:idx]
	credValue := creds[idx+1:]
	if credType != "token" && credType != "ssh_key" {
		fmt.Fprintf(os.Stderr, "  Warning: unknown credential type %q (expected \"token\" or \"ssh_key\")\n", credType)
		return "", ""
	}
	return credType, credValue
}

// buildAuditBody constructs the JSON body for POST /api/audits, including
// optional webhook URL from CI flags.
func buildAuditBody(sourceID string, types []string, ci ciFlags) map[string]interface{} {
	body := map[string]interface{}{
		"source_id": sourceID,
		"types":     types,
	}
	if ci.webhook != "" {
		body["webhook_url"] = ci.webhook
	}
	return body
}

// pollUntilDone polls GET /api/audits/:id every 3 seconds until the audit
// reaches a terminal status (completed or failed).
func pollUntilDone(apiURL, auditID, token string) audit {
	url := apiURL + "/api/audits/" + auditID
	for {
		a := apiGet[audit](url, token)
		if a.Status == "completed" || a.Status == "failed" {
			return a
		}
		fmt.Fprintf(os.Stderr, "  Status: %s ...\n", a.Status)
		time.Sleep(3 * time.Second)
	}
}

// outputResult writes the audit result to stdout. If --output json, it emits
// the full audit as JSON. Otherwise it calls printAuditSummary (text to stderr+stdout).
func outputResult(a audit, ci ciFlags) {
	if ci.output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(a)
		return
	}
	printAuditSummary(a)
}

// computeExitCode returns 1 if any finding meets or exceeds the given severity
// threshold, 0 otherwise. Returns 0 if exitOn is empty.
func computeExitCode(a audit, exitOn string) int {
	if exitOn == "" {
		return 0
	}
	severityRank := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}
	threshold, ok := severityRank[exitOn]
	if !ok {
		fmt.Fprintf(os.Stderr, "  Warning: unknown severity %q for --exit-on (expected critical, high, medium, low)\n", exitOn)
		return 0
	}
	for _, f := range a.Findings {
		if severityRank[f.Severity] >= threshold {
			return 1
		}
	}
	return 0
}

// --- Helpers ---

// agentDisplayName returns the human-friendly name for an agent type.
// Falls back to strings.ToUpper for short acronym-like types (e.g. "ssdf" → "SSDF").
func agentDisplayName(agentType string) string {
	for _, a := range agentregistry.AllAgents {
		if a.Type == agentType {
			return a.Name
		}
	}
	if len(agentType) <= 6 {
		return strings.ToUpper(agentType)
	}
	return strings.ToUpper(agentType[:1]) + agentType[1:]
}

// joinAgentNames maps a slice of agent types to display names and joins them.
func joinAgentNames(types []string) string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = agentDisplayName(t)
	}
	return strings.Join(names, ", ")
}

func streamAudit(apiURL, auditID, token string) {
	url := apiURL + "/api/audits/" + auditID + "/stream"
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		fatalf("Stream connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		fatalf("Stream error (%d): %s", resp.StatusCode, string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var eventType string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			printSSEEvent(eventType, data)
		}
	}
}

func printSSEEvent(eventType, data string) {
	var evt map[string]interface{}
	json.Unmarshal([]byte(data), &evt)

	switch eventType {
	case "RunStarted":
		fmt.Println("  Audit run started")
	case "StepStarted":
		printEvtField(evt, "stepName", "  \033[34m▶ Agent started: %s\033[0m\n")
	case "TextMessageContent":
		printDelta(evt)
	case "ToolCallStart":
		printEvtField(evt, "toolName", "    Scanning: %s\n")
	case "StateDelta":
		printStateDelta(evt)
	case "StateSnapshot":
		printStateSnapshot(evt)
	case "StepFinished":
		printEvtField(evt, "stepName", "  \033[32m✓ Agent finished: %s\033[0m\n")
	case "RunFinished":
		fmt.Println("  \033[32mAudit completed\033[0m")
	case "RunError":
		printEvtField(evt, "error", "  \033[31mERROR: %s\033[0m\n")
	}
}

// printEvtField prints a formatted string if the named field exists in the event.
func printEvtField(evt map[string]interface{}, field, format string) {
	if val, ok := evt[field].(string); ok {
		fmt.Printf(format, val)
	}
}

// printDelta prints the text delta from a TextMessageContent event.
func printDelta(evt map[string]interface{}) {
	delta, ok := evt["delta"]
	if !ok {
		return
	}
	if s, ok := delta.(string); ok {
		fmt.Printf("    %s\n", s)
		return
	}
	// delta may be a JSON-encoded string
	raw, _ := json.Marshal(delta)
	var s string
	if json.Unmarshal(raw, &s) == nil {
		fmt.Printf("    %s\n", s)
	}
}

// printStateDelta prints findings from a JSON-patch style StateDelta event.
// Also handles wrapped token_savings and dedup_stats events.
func printStateDelta(evt map[string]interface{}) {
	delta, ok := evt["delta"]
	if !ok {
		return
	}
	// JSON-patch array → finding patches
	if arr, ok := delta.([]interface{}); ok {
		for _, patch := range arr {
			printFindingPatch(patch)
		}
		return
	}
	// Wrapped map events (token_savings, dedup_stats)
	m, ok := delta.(map[string]interface{})
	if !ok {
		return
	}
	if ts, ok := m["token_savings"].(map[string]interface{}); ok {
		printTokenSavings(ts)
	}
	if ds, ok := m["dedup_stats"].(map[string]interface{}); ok {
		printDedupStats(ds)
	}
}

// printTokenSavings displays memory-based token optimization stats.
func printTokenSavings(ts map[string]interface{}) {
	priorCount, _ := ts["prior_findings_used"].(float64)
	skipped, _ := ts["findings_skipped"].(float64)
	total, _ := ts["findings_total"].(float64)
	pct, _ := ts["savings_percent"].(float64)
	if priorCount > 0 || skipped > 0 {
		fmt.Printf("    \033[36m💾 Token savings: %d prior findings used", int(priorCount))
		if total > 0 {
			fmt.Printf(", %d/%d skipped (%.0f%% saved)", int(skipped), int(total), pct)
		}
		fmt.Printf("\033[0m\n")
	}
}

// printDedupStats displays deduplication metrics from skill-mode scanning.
func printDedupStats(ds map[string]interface{}) {
	deduped, _ := ds["findings_deduped"].(float64)
	prior, _ := ds["prior_findings_used"].(float64)
	if deduped > 0 || prior > 0 {
		fmt.Printf("    \033[36m🔄 Dedup: %d findings deduped, %d prior findings used\033[0m\n", int(deduped), int(prior))
	}
}

// printFindingPatch prints a single finding from a JSON patch operation.
func printFindingPatch(patch interface{}) {
	p, ok := patch.(map[string]interface{})
	if !ok || p["path"] != "/findings/-" {
		return
	}
	val, ok := p["value"].(map[string]interface{})
	if !ok {
		return
	}
	sev, _ := val["severity"].(string)
	title, _ := val["title"].(string)
	fmt.Printf("    \033[33m⚠ Finding [%s]: %s\033[0m\n", strings.ToUpper(sev), title)
}

// printStateSnapshot prints a summary of a full state snapshot from an agent.
func printStateSnapshot(evt map[string]interface{}) {
	snapshot, ok := evt["snapshot"].(map[string]interface{})
	if !ok {
		return
	}
	count := 0
	if findings, ok := snapshot["findings"].([]interface{}); ok {
		count = len(findings)
	}
	agent, _ := evt["agentType"].(string)
	fmt.Printf("    Results: %s found %d findings\n", agentDisplayName(agent), count)
}

// findingCount returns the total finding count, using the full slice length or the summary count.
func (a audit) findingCount() int {
	if len(a.Findings) > 0 {
		return len(a.Findings)
	}
	return a.FindingsCount
}

func printAuditSummary(a audit) {
	fmt.Printf("\n  Audit: %s\n", a.ID)
	fmt.Printf("  Status: %s\n", colorStatus(a.Status))
	fmt.Printf("  Types: %s\n", joinAgentNames(a.Types))
	fmt.Printf("  Findings: %d\n", a.findingCount())

	if len(a.Scores) > 0 {
		fmt.Print("  Scores: ")
		parts := make([]string, 0, len(a.Scores))
		for k, v := range a.Scores {
			parts = append(parts, fmt.Sprintf("%s=%d%%", k, v))
		}
		fmt.Println(strings.Join(parts, ", "))
	}

	// Severity breakdown
	sev := map[string]int{}
	for _, f := range a.Findings {
		sev[f.Severity]++
	}
	if len(sev) > 0 {
		fmt.Print("  Severity: ")
		parts := make([]string, 0)
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if c, ok := sev[s]; ok {
				parts = append(parts, fmt.Sprintf("%s=%d", s, c))
			}
		}
		fmt.Println(strings.Join(parts, ", "))
	}

	// Show UI link
	frontendURL := os.Getenv("VULTURE_FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = defaultFrontendURL
	}
	fmt.Printf("\n  View in UI: %s/audit/%s\n", frontendURL, a.ID)

	// Show local dev credentials if frontend is running locally
	if isLocalMode(frontendURL) {
		fmt.Println()
		fmt.Println("  Local dev credentials:")
		fmt.Println("    Email:    admin@vulture.local")
		fmt.Println("    Password: REDACTED-DEV-PW")
	}
}

func colorStatus(status string) string {
	switch status {
	case "completed":
		return "\033[32m" + status + "\033[0m"
	case "running":
		return "\033[34m" + status + "\033[0m"
	case "failed":
		return "\033[31m" + status + "\033[0m"
	default:
		return "\033[33m" + status + "\033[0m"
	}
}

func colorSeverity(severity string) string {
	switch severity {
	case "critical":
		return "\033[31mCRITICAL\033[0m"
	case "high":
		return "\033[33mHIGH\033[0m"
	case "medium":
		return "\033[35mMEDIUM\033[0m"
	case "low":
		return "\033[36mLOW\033[0m"
	default:
		return severity
	}
}

// --- API helpers ---

// apiDo executes an HTTP request with auth, checks for errors, and returns the response body reader.
func apiDo(req *http.Request, token string) *http.Response {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("Request failed: %v", err)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
		// Feature 0039: 503 from /api/audits when VULTURE_REQUIRE_LLM=true
		// and LLM is unreachable. Surface the canonical message verbatim
		// to stderr and exit 75 (EX_TEMPFAIL) so CI can distinguish a
		// retriable LLM outage from a genuine error.
		if resp.StatusCode == http.StatusServiceUnavailable {
			tempFailf(string(body))
		}
		fatalf("API error (%d): %s", resp.StatusCode, string(body))
	}
	return resp
}

// tempFailf writes the message to stderr and exits with code 75 (EX_TEMPFAIL).
// Used when the server signals a transient condition like LLM unreachable in
// strict mode — CI integrations can map exit-code 75 to "retry later".
func tempFailf(message string) {
	fmt.Fprintf(os.Stderr, "\n  %s\n\n", message)
	os.Exit(75)
}

func apiPost[T any](url string, body []byte, token string) T {
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := apiDo(req, token)
	defer resp.Body.Close()
	var result T
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func apiGet[T any](url string, token string) T {
	req, _ := http.NewRequest("GET", url, nil)
	resp := apiDo(req, token)
	defer resp.Body.Close()
	var result T
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func apiDelete(url string, token string) {
	req, _ := http.NewRequest("DELETE", url, nil)
	resp := apiDo(req, token)
	resp.Body.Close()
}

// --- Token management ---

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, configDir)
}

func saveToken(token string) {
	dir := configPath()
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, tokenFile), []byte(token), 0600)
}

func loadToken() string {
	data, err := os.ReadFile(filepath.Join(configPath(), tokenFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func truncateID(id string, maxLen int) string {
	if len(id) > maxLen {
		return id[:maxLen]
	}
	return id
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\n  Error: "+format+"\n\n", args...)
	os.Exit(1)
}

// --- config.ini helpers ---

// cliResolve reads a value from config.ini with fallback, prepending a URL prefix.
func cliResolve(section, key, fallback, prefix string) string {
	val := cliINIValue(section, key, fallback)
	return prefix + val
}

// cliINIValue reads a single value from config.ini. Returns fallback if absent.
func cliINIValue(section, key, fallback string) string {
	path := cliINIPath()
	if path == "" {
		return fallback
	}
	vals := cliLoadINI(path)
	if v, ok := vals[section+"."+key]; ok && v != "" {
		return v
	}
	return fallback
}

func cliINIPath() string {
	return iniutil.FindINIPath()
}

func cliLoadINI(path string) map[string]string {
	return iniutil.ParseINI(path)
}
