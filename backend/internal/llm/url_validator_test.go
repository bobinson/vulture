package llm

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateEndpointEmpty(t *testing.T) {
	if err := ValidateEndpoint(""); err != nil {
		t.Fatalf("empty endpoint should be allowed, got: %v", err)
	}
}

func TestValidateEndpointHTTPS(t *testing.T) {
	for _, ok := range []string{
		"https://api.openai.com/v1",
		"https://api.anthropic.com",
		"https://my-llm-proxy.example.com:8443/v1",
	} {
		if err := ValidateEndpoint(ok); err != nil {
			t.Errorf("https endpoint %q rejected: %v", ok, err)
		}
	}
}

func TestValidateEndpointLoopbackHTTP(t *testing.T) {
	for _, ok := range []string{
		"http://127.0.0.1:1234/v1",
		"http://localhost:11434",
		"http://[::1]:8080",
		"http://0.0.0.0:8080",
	} {
		if err := ValidateEndpoint(ok); err != nil {
			t.Errorf("loopback endpoint %q rejected: %v", ok, err)
		}
	}
}

func TestValidateEndpointInsecureRemote(t *testing.T) {
	bad := []string{
		"http://attacker.example/v1",
		"http://api.openai.com/v1", // even a real provider via http is rejected
		"http://192.168.1.50:1234",
		"http://10.0.0.1",
	}
	for _, b := range bad {
		err := ValidateEndpoint(b)
		if err == nil {
			t.Errorf("ValidateEndpoint(%q) = nil, want error", b)
		}
		if !errors.Is(err, ErrInsecureEndpoint) {
			t.Errorf("ValidateEndpoint(%q): err is not ErrInsecureEndpoint", b)
		}
	}
}

func TestValidateEndpointWrongScheme(t *testing.T) {
	for _, b := range []string{
		"ftp://api.example.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
	} {
		err := ValidateEndpoint(b)
		if err == nil {
			t.Errorf("ValidateEndpoint(%q) = nil, want error", b)
		}
	}
}

func TestValidateEndpointMalformed(t *testing.T) {
	// url.Parse is forgiving; only severely-malformed inputs error.
	if err := ValidateEndpoint("ht tps://x"); err == nil {
		t.Errorf("badly-formed scheme should error")
	}
}

func TestValidateAll(t *testing.T) {
	good := map[string]string{
		"OPENAI_BASE_URL": "https://api.openai.com/v1",
		"OLLAMA_HOST":     "http://127.0.0.1:11434",
	}
	if err := ValidateAll(good); err != nil {
		t.Errorf("ValidateAll(good) = %v, want nil", err)
	}

	bad := map[string]string{
		"OLLAMA_HOST":     "http://127.0.0.1:11434",
		"OPENAI_BASE_URL": "http://attacker.example/v1",
	}
	err := ValidateAll(bad)
	if err == nil {
		t.Fatal("ValidateAll(bad) = nil, want error")
	}
	if !strings.Contains(err.Error(), "OPENAI_BASE_URL") {
		t.Errorf("ValidateAll error should name the bad var, got: %v", err)
	}
}
