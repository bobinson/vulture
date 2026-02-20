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
		respBody, _ := io.ReadAll(resp.Body)
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
		respBody, _ := io.ReadAll(resp.Body)
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
