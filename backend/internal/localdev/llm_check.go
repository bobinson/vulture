package localdev

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// agentLLMHealth captures the relevant fields from an agent's /health.
// Mirrors handler.LLMHealthResponse but defined locally to avoid pulling
// the whole handler package into localdev.
type agentLLMHealth struct {
	LLM struct {
		Provider  string `json:"provider"`
		Reachable bool   `json:"reachable"`
	} `json:"llm"`
	LLMMessage string `json:"llm_message"`
}

// reportLLMHealthOrAbort polls the first running agent's /health endpoint
// (max 15s wait), prints the canonical message with a ✓ or ⚠ marker, and
// — when VULTURE_REQUIRE_LLM=true and LLM is unreachable — aborts startup
// via log.Fatal. Otherwise warns and continues (today's behaviour).
//
// Implements feature 0039 Phase 4. The canonical message is the same
// string the frontend banner / per-audit response will display, so users
// see the exact same text wherever they look.
func reportLLMHealthOrAbort(ctx context.Context, agentURLs []string) {
	if len(agentURLs) == 0 {
		log.Printf("  ⚠ no agents configured — cannot probe LLM health")
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	client := &http.Client{Timeout: 4 * time.Second}

	for time.Now().Before(deadline) {
		for _, url := range agentURLs {
			body, ok := tryGetAgentLLM(ctx, client, url)
			if !ok {
				continue
			}
			marker := "✓"
			if body.LLM.Provider != "disabled" && !body.LLM.Reachable {
				marker = "⚠"
			}
			log.Printf("  %s %s", marker, body.LLMMessage)

			if os.Getenv("VULTURE_REQUIRE_LLM") == "true" && !body.LLM.Reachable && body.LLM.Provider != "disabled" {
				log.Fatalf("VULTURE_REQUIRE_LLM=true and LLM unreachable; aborting startup")
			}
			return
		}
		time.Sleep(1 * time.Second)
	}
	log.Printf("  ⚠ could not query any agent for LLM health within 15s; continuing")
}

func tryGetAgentLLM(ctx context.Context, client *http.Client, url string) (*agentLLMHealth, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/health", nil)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var body agentLLMHealth
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false
	}
	// Skip agents that don't report the new llm field (older shape).
	if body.LLMMessage == "" {
		return nil, false
	}
	_ = fmt.Sprintf // keep fmt import for future formatting use
	return &body, true
}
