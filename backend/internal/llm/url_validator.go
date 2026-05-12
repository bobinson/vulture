// Package llm contains helpers around LLM endpoint configuration —
// primarily URL validation that runs at daemon startup so an attacker
// who slipped a malicious OPENAI_BASE_URL into the environment cannot
// silently exfiltrate API keys.
package llm

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInsecureEndpoint indicates the configured LLM endpoint would
// transmit API keys in cleartext to a remote host. See plan
// invariant S5.
var ErrInsecureEndpoint = errors.New(
	"LLM endpoint is http:// to a non-loopback host (API keys would be " +
		"sent in cleartext); use https:// or http://127.0.0.1:*; bypass " +
		"with VULTURE_ALLOW_INSECURE_LLM=true")

// loopbackHosts are the hostnames that count as "local; cleartext is
// fine because nothing leaves the box."
var loopbackHosts = map[string]struct{}{
	"127.0.0.1": {},
	"localhost": {},
	"::1":       {},
	"[::1]":     {},
	"0.0.0.0":   {}, // bound-to-everything from the kernel's POV; still local
}

// ValidateEndpoint returns nil iff raw is acceptable as an LLM
// endpoint. Empty input is OK (means "no override"). https:// to any
// host is OK. http:// is OK only to loopback. Anything else is
// rejected.
func ValidateEndpoint(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse endpoint %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if _, ok := loopbackHosts[host]; ok {
			return nil
		}
		return fmt.Errorf("%w (host %q)", ErrInsecureEndpoint, host)
	default:
		return fmt.Errorf("endpoint scheme must be http or https, got %q", u.Scheme)
	}
}

// ValidateAll checks every configured endpoint and returns the first
// error encountered, or nil. Caller passes a map of `name -> url`
// so the error message identifies which env var was bad.
func ValidateAll(endpoints map[string]string) error {
	for name, raw := range endpoints {
		if err := ValidateEndpoint(raw); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}
