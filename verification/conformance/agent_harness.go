package conformance

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// AgentResult holds structured output from running an agent.
type AgentResult struct {
	Findings     []AgentFinding
	EndpointCount int
	URLCount     int
	Status       string
}

// AgentFinding is a single finding from an agent.
type AgentFinding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

// AgentProcess manages a Python agent subprocess.
type AgentProcess struct {
	cmd  *exec.Cmd
	port string
}

// StartAgent launches a Python agent via uvicorn.
// agentDir is the agent directory (e.g. agents/discover).
// The shared library path is derived as agentDir/../shared.
func StartAgent(agentDir, module, port string) (*AgentProcess, error) {
	sharedDir, _ := filepath.Abs(filepath.Join(agentDir, "..", "shared"))
	pythonPath := agentDir + string(os.PathListSeparator) + sharedDir
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath = pythonPath + string(os.PathListSeparator) + existing
	}

	cmd := exec.Command("uvicorn", module,
		"--host", "127.0.0.1", "--port", port,
		"--log-level", "warning",
	)
	cmd.Dir = agentDir
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+pythonPath,
		"VULTURE_AGENT_PORT="+port,
		"VULTURE_USE_LLM=false",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}

	ap := &AgentProcess{cmd: cmd, port: port}
	if err := ap.waitHealthy(15 * time.Second); err != nil {
		ap.Stop()
		return nil, err
	}
	return ap, nil
}

func (ap *AgentProcess) waitHealthy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%s/health", ap.port)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("agent not healthy after %v on port %s", timeout, ap.port)
}

// Stop kills the agent process.
func (ap *AgentProcess) Stop() {
	if ap.cmd != nil && ap.cmd.Process != nil {
		ap.cmd.Process.Kill()
		ap.cmd.Wait()
	}
}

// RunAgent calls POST /run and collects SSE events.
func RunAgent(port string, request map[string]interface{}) (*AgentResult, error) {
	reqJSON, _ := json.Marshal(request)
	url := fmt.Sprintf("http://127.0.0.1:%s/run", port)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("POST /run: %w", err)
	}
	defer resp.Body.Close()

	result := &AgentResult{}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0), 1024*1024) // 1MB buffer for large SSE events
	var eventType string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			eventType = ""
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
			continue
		}
		if strings.HasPrefix(line, "data: ") && eventType != "" {
			parseAgentEvent(eventType, line[6:], result)
		}
	}
	return result, scanner.Err()
}

func parseAgentEvent(eventType, data string, result *AgentResult) {
	switch eventType {
	case "finding":
		var f AgentFinding
		if json.Unmarshal([]byte(data), &f) == nil && f.Title != "" {
			result.Findings = append(result.Findings, f)
		}
	case "discover_result":
		var dr struct {
			URLCount int `json:"url_count"`
			APICount int `json:"api_count"`
		}
		if json.Unmarshal([]byte(data), &dr) == nil {
			result.EndpointCount = dr.APICount
			result.URLCount = dr.URLCount
		}
	case "agent_end":
		result.Status = "completed"
	}
}
