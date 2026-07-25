//go:build lmstudio

package server_test

// Extended end-to-end broker→LMStudio coverage (feature 0064 §32.1): the paths
// that broke in production — a MULTI-TURN TOOL LOOP (assistant tool_calls
// replayed → tool result, exercising the outbound nested-tool_call wire #9c and
// inbound parse #9b) and a REAL vulture-source scan through the full broker
// pipeline against a live model. Same harness as TestE2E_Broker_LMStudio.
//
//   go test -tags=lmstudio -run TestE2E_Broker_LMStudio ./internal/broker/server/ -v

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/server"
	"github.com/vulture/backend/internal/broker/token"
)

// lmStudioBrokerServer builds the full broker server wired to real LMStudio via
// the openai-compatible adapter, plus a minted token scoped to the model.
func lmStudioBrokerServer(t *testing.T) (*server.Server, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	h := newHealthyHarness()
	minter, err := token.NewMinter(privPEM, "e2e-kid")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	verifier, err := token.NewVerifier(map[string][]byte{"e2e-kid": pubPEM}, h.denylist, h.revocation)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok, err := minter.Mint(token.MintRequest{
		RunID: "run-e2e-ext", TenantID: "local", Scope: []string{"scan:" + lmStudioModel}, TTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.selector.sel = &egress.ModelSelection{Model: lmStudioModel}
	h.ssrf.target = &egress.PinnedTarget{URL: lmStudioBaseURL, Provider: "openai"}
	srv := server.New(server.Dependencies{
		Verifier: verifier, Denylist: h.denylist, Revocation: h.revocation,
		Budget: h.budget, Selector: h.selector, SSRF: h.ssrf, Allowlist: h.allowlist,
		Adapters: map[string]provider.Adapter{
			"openai": provider.NewOpenAICompatibleAdapter("openai", &http.Client{Timeout: 180 * time.Second}),
		},
		Breakers: singleBreakerPool{h.breaker}, Bulkheads: singleBulkheadPool{h.bulkhead}, Retriers: singleRetrierPool{h.retrier},
		CallTimeoutSec: 180,
	})
	return srv, tok
}

func respContentUsage(t *testing.T, rr interface{ Bytes() []byte }) (string, map[string]any) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rr.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var content string
	if choices, _ := out["choices"].([]any); len(choices) > 0 {
		if ch, ok := choices[0].(map[string]any); ok {
			if msg, ok := ch["message"].(map[string]any); ok {
				content, _ = msg["content"].(string)
			}
		}
	}
	usage, _ := out["usage"].(map[string]any)
	return content, usage
}

// Multi-turn tool loop: assistant replays a tool_call (nested on the wire), then
// a tool result. The provider must ACCEPT the request (the flat-tool_call bug
// would corrupt the history). Asserts 200 + real usage through the broker.
func TestE2E_Broker_LMStudio_MultiTurnToolLoop(t *testing.T) {
	srv, tok := lmStudioBrokerServer(t)
	body := completeBody()
	body["model_hint"] = lmStudioModel
	body["max_tokens"] = 64
	body["messages"] = []map[string]any{
		{"role": "system", "content": "You are a code auditor."},
		{"role": "user", "content": "List Go files under the source root."},
		{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
			{"id": "call_0", "type": "function", "function": map[string]any{"name": "list_files", "arguments": `{"path":"."}`}},
		}},
		{"role": "tool", "tool_call_id": "call_0", "name": "list_files", "content": "main.go\nconfig.go"},
	}
	body["tools"] = []map[string]any{
		{"type": "function", "function": map[string]any{
			"name": "list_files", "description": "list files",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}, "required": []any{"path"}},
		}},
	}
	rr := doPost(t, srv, completePath, "Bearer "+tok, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("multi-turn tool loop status=%d body=%q", rr.Code, rr.Body.String())
	}
	content, usage := respContentUsage(t, rr.Body)
	t.Logf("broker→LMStudio multi-turn OK: content=%q usage=%v", content, usage)
	if usage == nil {
		t.Fatalf("no usage (floor would reject): %s", rr.Body.String())
	}
}

// Real vulture-source scan: feed an actual source file from this repo and ask
// for CWE findings through the full broker pipeline. Proves an end-to-end audit
// LLM call against a live model over the broker.
func TestE2E_Broker_LMStudio_ScanVultureSource(t *testing.T) {
	srv, tok := lmStudioBrokerServer(t)
	// A real file from THIS repo (the broker's own error mapping).
	src, err := os.ReadFile("errors.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	snippet := string(src)
	if len(snippet) > 6000 {
		snippet = snippet[:6000]
	}
	body := completeBody()
	body["model_hint"] = lmStudioModel
	body["max_tokens"] = 256
	body["messages"] = []map[string]any{
		{"role": "system", "content": "You are a security auditor. Reply with ONE short sentence naming the file's purpose."},
		{"role": "user", "content": "Summarize the purpose of this Go source in one sentence:\n\n" + snippet},
	}
	rr := doPost(t, srv, completePath, "Bearer "+tok, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("scan status=%d body=%q", rr.Code, rr.Body.String())
	}
	content, usage := respContentUsage(t, rr.Body)
	t.Logf("broker→LMStudio scan OK: usage=%v content=%q", usage, strings.TrimSpace(content)[:min(160, len(strings.TrimSpace(content)))])
	if strings.TrimSpace(content) == "" || usage == nil {
		t.Fatalf("empty scan completion or no usage: %s", rr.Body.String())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
