package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultAPIURL = "http://localhost:8080"
	configDir     = ".vulture"
	tokenFile     = "token"
)

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
}

type cacheResponse struct {
	Cached bool  `json:"cached"`
	Audit  audit `json:"audit"`
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
			fmt.Fprintln(os.Stderr, "Usage: vulture scan <path-or-git-url> [--types chaos,owasp,soc2,cwe] [--no-cache]")
			os.Exit(1)
		}
		types, noCache := parseScanFlags(os.Args[3:])
		cmdScan(apiURL, os.Args[2], types, noCache)
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
		types, noCache := parseScanFlags(os.Args[2:])
		cmdScan(apiURL, cmd, types, noCache)
	}
}

// parseScanFlags extracts --types and --no-cache from arguments.
func parseScanFlags(args []string) (types []string, noCache bool) {
	types = []string{"chaos", "owasp", "soc2", "cwe"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--types":
			if i+1 < len(args) {
				types = strings.Split(args[i+1], ",")
				i++ // skip value
			}
		case "--no-cache":
			noCache = true
		}
	}
	return
}

func printUsage() {
	fmt.Println(`Vulture CLI - Compliance Audit Platform

Usage:
  vulture login                          Authenticate with the Vulture server
  vulture scan <path-or-url> [--types]   Scan source code for compliance issues
  vulture <path-or-url>                  Shorthand for scan
  vulture localstart                     Start all services locally (backend + agents + frontend)
  vulture localstop                      Stop all locally running services
  vulture status                         Show recent audit statuses
  vulture results <audit-id>             Show detailed results for an audit

Options:
  --types chaos,owasp,soc2,cwe  Comma-separated audit types (default: all)
  --no-cache                  Force fresh audit, skip cached results

Environment:
  VULTURE_API_URL             API server URL (default: http://localhost:8080)

Examples:
  vulture login
  vulture scan /home/user/project
  vulture scan https://github.com/org/repo.git --types owasp,soc2,cwe
  vulture localstart
  vulture /home/user/project
  vulture status
  vulture results abc123`)
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

var localServices = []struct {
	name string
	port string
}{
	{"backend", "8080"},
	{"agent-chaos", "8001"},
	{"agent-owasp", "8002"},
	{"agent-soc2", "8003"},
	{"agent-cwe", "8004"},
	{"frontend", "3001"},
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
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(apiURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fatalf("Connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
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

func cmdScan(apiURL string, target string, types []string, noCache bool) {
	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}

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
	}

	fmt.Printf("  Submitting source (%s): %s\n", srcType, target)

	// Create source
	srcBody := map[string]string{"type": srcType}
	if srcType == "git" {
		srcBody["url"] = target
	} else {
		srcBody["path"] = target
	}
	srcJSON, _ := json.Marshal(srcBody)
	src := apiPost[source](apiURL+"/api/sources", srcJSON, token)
	fmt.Printf("  Source created: %s (%d files)\n", truncateID(src.ID, 12), src.FileCount)

	// Check for cached results
	if !noCache {
		cacheURL := fmt.Sprintf("%s/api/audits/cache?source_id=%s&types=%s", apiURL, src.ID, strings.Join(types, ","))
		cached := apiGet[cacheResponse](cacheURL, token)
		if cached.Cached && cached.Audit.ID != "" {
			fmt.Printf("\n  \033[33m⚡ Cached results found (audit %s)\033[0m\n", truncateID(cached.Audit.ID, 12))
			fmt.Printf("  Completed: %s\n", cached.Audit.CompletedAt)
			fmt.Printf("  Use --no-cache to force a fresh audit\n")
			fmt.Println(strings.Repeat("-", 60))
			printAuditSummary(cached.Audit)
			return
		}
	}

	// Create audit
	auditBody, _ := json.Marshal(map[string]interface{}{
		"source_id": src.ID,
		"types":     types,
	})
	a := apiPost[audit](apiURL+"/api/audits", auditBody, token)
	fmt.Printf("  Audit started: %s\n", truncateID(a.ID, 12))
	fmt.Printf("  Types: %s\n\n", strings.Join(types, ", "))

	// Stream results
	fmt.Println("  Streaming results...")
	fmt.Println(strings.Repeat("-", 60))
	streamAudit(apiURL, a.ID, token)

	// Fetch final results
	fmt.Println(strings.Repeat("-", 60))
	final := apiGet[audit](apiURL+"/api/audits/"+a.ID, token)
	printAuditSummary(final)
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
			strings.Join(a.Types, ","),
			findCount,
			date,
		)
	}
	fmt.Println()
}

func cmdResults(apiURL string, id string) {
	token := loadToken()
	if token == "" && isLocalMode(apiURL) {
		token = autoLoginLocal(apiURL)
	}
	a := apiGet[audit](apiURL+"/api/audits/"+id, token)
	printAuditSummary(a)

	if len(a.Findings) > 0 {
		fmt.Println("\n  FINDINGS:")
		fmt.Println("  " + strings.Repeat("-", 70))
		for i, f := range a.Findings {
			sev := colorSeverity(f.Severity)
			fmt.Printf("  %d. [%s] %s\n", i+1, sev, f.Title)
			fmt.Printf("     File: %s:%d\n", f.FilePath, f.LineStart)
			fmt.Printf("     Category: %s | Agent: %s\n", f.Category, f.AgentType)
			if f.Recommendation != "" {
				fmt.Printf("     Fix: %s\n", f.Recommendation)
			}
			fmt.Println()
		}
	}
}

// --- Helpers ---

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
		body, _ := io.ReadAll(resp.Body)
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
func printStateDelta(evt map[string]interface{}) {
	delta, ok := evt["delta"]
	if !ok {
		return
	}
	arr, ok := delta.([]interface{})
	if !ok {
		return
	}
	for _, patch := range arr {
		printFindingPatch(patch)
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
	fmt.Printf("    Results: %s found %d findings\n", agent, count)
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
	fmt.Printf("  Types: %s\n", strings.Join(a.Types, ", "))
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
		frontendURL = "http://localhost:3001"
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
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fatalf("API error (%d): %s", resp.StatusCode, string(body))
	}
	return resp
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

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\n  Error: "+format+"\n\n", args...)
	os.Exit(1)
}
