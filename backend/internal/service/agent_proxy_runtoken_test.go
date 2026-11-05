package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// Feature 0102: the proxy sends the run token it was built with, never a value
// read from the process environment per request.
func TestAgentProxyWithTokens_SendsRunTokensNotProcessEnv(t *testing.T) {
	t.Setenv("VULTURE_AGENT_TOKEN", "process-env-value")
	proxy := NewAgentProxyServiceWithTokens(nil, pluginregistry.NewRunTokens("configured-shared", nil))

	for agentType, want := range map[string]string{
		"cwe":     "configured-shared",
		"semgrep": pluginregistry.PluginRunToken("configured-shared", "semgrep"),
	} {
		if got, sent := runTokenHeader(t, proxy, agentType); !sent || got != want {
			t.Errorf("%s: token header sent=%v value=%q, want %q", agentType, sent, got, want)
		}
	}
}

func TestAgentProxyWithTokens_ZeroTokensSendNoHeader(t *testing.T) {
	t.Setenv("VULTURE_AGENT_TOKEN", "process-env-value")
	proxy := NewAgentProxyServiceWithTokens(nil, pluginregistry.RunTokens{})

	for _, agentType := range []string{"cwe", "semgrep"} {
		if _, sent := runTokenHeader(t, proxy, agentType); sent {
			t.Errorf("%s: a token header was sent although the proxy holds no token", agentType)
		}
	}
}

// runTokenHeader dispatches one run and reports the X-Vulture-Agent-Token
// header the agent received, and whether it was present at all.
func runTokenHeader(t *testing.T, proxy AgentProxyService, agentType string) (string, bool) {
	t.Helper()
	received := make(chan []string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Values("X-Vulture-Agent-Token")
		w.Header().Set("Content-Type", "text/event-stream")
	}))
	defer srv.Close()
	ch := make(chan *model.AgUIEvent, 10)
	if err := proxy.RunAgent(context.Background(), srv.URL, agentType, "run-token", "/src", json.RawMessage(`{}`), ch); err != nil {
		t.Fatalf("run %s: %v", agentType, err)
	}
	values := <-received
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}
