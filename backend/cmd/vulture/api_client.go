package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

func submitSource(apiURL, sourceType, target string) (string, error) {
	payload := map[string]string{"type": sourceType}
	if sourceType == "git" {
		payload["url"] = target
	} else {
		payload["path"] = target
	}
	body, _ := json.Marshal(payload)

	resp, err := httpClient.Post(apiURL+"/api/sources", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST /api/sources: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("submit source: status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode source response: %w", err)
	}
	return result.ID, nil
}

// streamClient holds the SSE connection open for a whole audit run.
var streamClient = &http.Client{Timeout: 20 * time.Minute}

// runAuditViaStream opens the audit's SSE stream, which TRIGGERS the run.
// In install/local mode an audit is not auto-run on creation — a stream
// connection is what kicks off runLiveAudit on the backend. We drain the
// stream until the server closes it (run complete), discarding events.
func runAuditViaStream(apiURL, auditID string) error {
	resp, err := streamClient.Get(apiURL + "/api/audits/" + auditID + "/stream")
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("stream status %d: %s", resp.StatusCode, string(b))
	}
	_, _ = io.Copy(io.Discard, resp.Body) // blocks until the run completes
	return nil
}

// auditSummary fetches a completed audit and tallies findings per agent.
func auditSummary(apiURL, auditID string) (status string, total int, byAgent map[string]int, err error) {
	resp, err := httpClient.Get(apiURL + "/api/audits/" + auditID)
	if err != nil {
		return "", 0, nil, err
	}
	defer resp.Body.Close()
	var a struct {
		Status   string `json:"status"`
		Findings []struct {
			AgentType string `json:"agent_type"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return "", 0, nil, err
	}
	byAgent = map[string]int{}
	for _, f := range a.Findings {
		byAgent[f.AgentType]++
	}
	return a.Status, len(a.Findings), byAgent, nil
}

func createAudit(apiURL, sourceID string, types []string) (string, error) {
	payload := map[string]interface{}{
		"source_id": sourceID,
		"types":     types,
		"config":    map[string]interface{}{},
	}
	body, _ := json.Marshal(payload)

	resp, err := httpClient.Post(apiURL+"/api/audits", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST /api/audits: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("create audit: status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode audit response: %w", err)
	}
	return result.ID, nil
}
