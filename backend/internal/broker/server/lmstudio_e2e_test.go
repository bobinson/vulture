//go:build lmstudio

package server_test

// End-to-end verification of the 0064 broker against a locally-running LMStudio.
//
// REAL components exercised: ES256 mint + verify (real P-256 crypto), the full
// server pipeline (auth → kid/denylist → scope → egress → budget reserve →
// resilience → adapter → usage-sanity floor → reconcile), and the
// OpenAI-compatible provider adapter talking to LMStudio.
//
// Doubles (each unit-tested elsewhere, not the subject here): budget Manager,
// resilience wrappers, model selector. SSRF uses a PERMISSIVE double on purpose
// — the real egress guard (correctly) blocks loopback, and LMStudio is on
// localhost; this test isolates the LLM-provider leg, not the SSRF guard.
//
// Requires LMStudio serving an OpenAI-compatible API at localhost:1234 with a
// chat model. Run:
//   go test -tags=lmstudio -run TestE2E_Broker_LMStudio ./internal/broker/server/ -v

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/vulture/backend/internal/broker/egress"
	"github.com/vulture/backend/internal/broker/provider"
	"github.com/vulture/backend/internal/broker/server"
	"github.com/vulture/backend/internal/broker/token"
)

const (
	lmStudioBaseURL = "http://localhost:1234/v1"
	lmStudioModel   = "openai/gpt-oss-20b"
)

func TestE2E_Broker_LMStudio(t *testing.T) {
	// Real ES256 keypair → real minter + verifier.
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
		RunID: "run-e2e", TenantID: "local", Scope: []string{"scan:" + lmStudioModel}, TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Point the (permissive) SSRF double + selector at LMStudio; use the REAL adapter.
	h.selector.sel = &egress.ModelSelection{Model: lmStudioModel}
	h.ssrf.target = &egress.PinnedTarget{URL: lmStudioBaseURL, Provider: "openai"}

	srv := server.New(server.Dependencies{
		Verifier: verifier, Denylist: h.denylist, Revocation: h.revocation,
		Budget: h.budget, Selector: h.selector, SSRF: h.ssrf, Allowlist: h.allowlist,
		Adapters: map[string]provider.Adapter{
			"openai": provider.NewOpenAICompatibleAdapter("openai", &http.Client{Timeout: 90 * time.Second}),
		},
		Breakers: singleBreakerPool{h.breaker}, Bulkheads: singleBulkheadPool{h.bulkhead}, Retriers: singleRetrierPool{h.retrier},
		CallTimeoutSec: 90,
	})

	body := completeBody()
	body["model_hint"] = lmStudioModel
	body["max_tokens"] = 32
	body["messages"] = []map[string]any{{"role": "user", "content": "Reply with exactly the word: OK"}}

	rr := doPost(t, srv, completePath, "Bearer "+tok, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v; body=%q", err, rr.Body.String())
	}
	// OpenAI chat.completion shape (§26 C1): content in choices[0].message,
	// usage.completion_tokens.
	choices, _ := out["choices"].([]any)
	var content string
	if len(choices) > 0 {
		if ch, ok := choices[0].(map[string]any); ok {
			if msg, ok := ch["message"].(map[string]any); ok {
				content, _ = msg["content"].(string)
			}
		}
	}
	usage, _ := out["usage"].(map[string]any)
	t.Logf("broker → LMStudio OK: model=%v content=%q usage=%v", out["model"], content, usage)
	if content == "" {
		t.Fatalf("empty content from LMStudio via broker: %s", rr.Body.String())
	}
	if usage == nil {
		t.Fatalf("no usage in broker response (usage-sanity floor would reject): %s", rr.Body.String())
	}
	if ot, _ := usage["completion_tokens"].(float64); ot <= 0 {
		t.Fatalf("completion_tokens=%v, want >0 (real LMStudio usage): %s", usage["completion_tokens"], rr.Body.String())
	}
}
