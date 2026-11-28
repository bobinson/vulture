//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/internal/broker/serve"
	"github.com/vulture/backend/internal/config"
)

// Business contract: OPENAI_BASE_URL names an endpoint that speaks the OpenAI
// wire protocol. The LLM broker may take it as its upstream only for a provider
// that speaks that protocol. A native provider (Anthropic Messages, Gemini
// generateContent) is always called at its own endpoint. Inheriting the OpenAI
// gateway would send that provider's API key to whoever runs the gateway.
// Reproduced: `vulture.sh dev anthropic …` with an OpenAI-compatible gateway in
// .env sent the Anthropic key to that gateway and every call got a 401.

// brokerEnvKeys are cleared before each case so the developer's shell cannot
// leak into the result.
var brokerEnvKeys = []string{
	"OPENAI_BASE_URL",
	"VULTURE_USE_LLM",
	"VULTURE_LLM_BROKER",
	"VULTURE_LLM_BROKER_PROVIDER",
	"VULTURE_LLM_BROKER_PROVIDER_BASE_URL",
	"VULTURE_LLM_BROKER_ALLOW_LOCAL_EGRESS",
}

// loadDeploymentBroker loads configuration the way the binary does
// (config.Load), from the given config.ini text and environment, and returns
// the broker block.
func loadDeploymentBroker(t *testing.T, ini string, env map[string]string) config.BrokerConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte(ini), 0o600); err != nil {
		t.Fatalf("write config.ini: %v", err)
	}
	t.Setenv("VULTURE_CONFIG", path)
	for _, k := range brokerEnvKeys {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	return config.Load().Broker
}

const openAIGateway = "https://gateway.example.com/api/v3"

func TestBroker_NativeProviderEgressesToItsOwnEndpoint(t *testing.T) {
	cases := []struct {
		name, ini, provider, want string
	}{
		{"anthropic from env", "", "anthropic", "https://api.anthropic.com"},
		{"gemini from env", "", "gemini", "https://generativelanguage.googleapis.com/v1beta"},
		{"anthropic from config.ini", "[broker]\nprovider = anthropic\n", "", "https://api.anthropic.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]string{"VULTURE_USE_LLM": "true", "OPENAI_BASE_URL": openAIGateway}
			if c.provider != "" {
				env["VULTURE_LLM_BROKER_PROVIDER"] = c.provider
			}
			bc := loadDeploymentBroker(t, c.ini, env)
			if got := serve.EgressBaseURL(bc); got != c.want {
				t.Fatalf("broker egress = %q, want the provider's own endpoint %q (OPENAI_BASE_URL must not be inherited)", got, c.want)
			}
		})
	}
}

// A loopback OPENAI_BASE_URL (LM Studio left in .env) must not open local
// egress for a cloud provider either.
func TestBroker_NativeProviderGainsNoLocalEgressFromOpenAIBase(t *testing.T) {
	bc := loadDeploymentBroker(t, "", map[string]string{
		"VULTURE_USE_LLM":             "true",
		"OPENAI_BASE_URL":             "http://127.0.0.1:1234/v1",
		"VULTURE_LLM_BROKER_PROVIDER": "anthropic",
	})
	if bc.AllowLocalEgress {
		t.Fatal("an anthropic broker must not gain local egress from a loopback OPENAI_BASE_URL")
	}
	if got := serve.EgressBaseURL(bc); got != "https://api.anthropic.com" {
		t.Fatalf("broker egress = %q, want https://api.anthropic.com", got)
	}
}

// An explicit broker base URL is the operator's choice and still wins, for a
// native provider too (e.g. an Anthropic-compatible proxy).
func TestBroker_ExplicitBaseURLStillWinsForNativeProvider(t *testing.T) {
	bc := loadDeploymentBroker(t, "", map[string]string{
		"VULTURE_USE_LLM":                      "true",
		"OPENAI_BASE_URL":                      openAIGateway,
		"VULTURE_LLM_BROKER_PROVIDER":          "anthropic",
		"VULTURE_LLM_BROKER_PROVIDER_BASE_URL": "https://anthropic-proxy.example.com",
	})
	if got := serve.EgressBaseURL(bc); got != "https://anthropic-proxy.example.com" {
		t.Fatalf("broker egress = %q, want the explicit override", got)
	}
}

// OpenAI-wire providers keep deriving their upstream from OPENAI_BASE_URL: the
// LM Studio / vLLM / gateway setups depend on it.
func TestBroker_OpenAIWireProviderInheritsOpenAIBase(t *testing.T) {
	for _, provider := range []string{"", "openai", "openai-compatible", "my-local-server"} {
		t.Run("provider="+provider, func(t *testing.T) {
			env := map[string]string{"VULTURE_USE_LLM": "true", "OPENAI_BASE_URL": openAIGateway}
			if provider != "" {
				env["VULTURE_LLM_BROKER_PROVIDER"] = provider
			}
			bc := loadDeploymentBroker(t, "", env)
			if got := serve.EgressBaseURL(bc); got != openAIGateway {
				t.Fatalf("broker egress = %q, want OPENAI_BASE_URL %q", got, openAIGateway)
			}
		})
	}
}
