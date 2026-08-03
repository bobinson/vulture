package main

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/localdev"
)

// The scan command resolved `apiURL` (honouring VULTURE_API_URL, else the
// configured backend port), printed it, and then re-derived the "View results"
// link from a FRESH localdev.DefaultConfig — discarding both. That made the
// printed link disagree with the API the scan had just used:
//
//   - install mode on a non-default port: API said the real port, the link said
//     the 28080 default;
//   - VULTURE_API_URL pointing at a remote server: the link still said
//     "localhost";
//   - dev mode invoked outside the project tree: findProjectRoot() cannot see
//     docker-compose.yml, config.ini is never read, and the frontend port
//     silently falls back to the default.
//
// The link must be derived from the same origin the scan actually talked to.

func devCfg() *localdev.Config {
	return &localdev.Config{BackendPort: "28080", FrontendPort: "23001"}
}

func TestInstallModeUsesTheApiOrigin(t *testing.T) {
	// Install mode serves the UI from the backend, so the API origin IS the UI
	// origin — whatever port it is actually on.
	got := auditResultsURL("http://localhost:29000", localdev.ModeInstall, devCfg(), "abc")
	want := "http://localhost:29000/audit/abc"
	if got != want {
		t.Fatalf("install mode must follow the real API port\n got: %s\nwant: %s", got, want)
	}
}

func TestInstallModeFollowsARemoteServer(t *testing.T) {
	got := auditResultsURL("https://vulture.example.com", localdev.ModeInstall, devCfg(), "abc")
	want := "https://vulture.example.com/audit/abc"
	if got != want {
		t.Fatalf("a remote API must not produce a localhost link\n got: %s\nwant: %s", got, want)
	}
}

func TestInstallModeTrimsTrailingSlash(t *testing.T) {
	got := auditResultsURL("http://localhost:28080/", localdev.ModeInstall, devCfg(), "abc")
	want := "http://localhost:28080/audit/abc"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestDevModeKeepsTheApiHostButUsesTheFrontendPort(t *testing.T) {
	// Dev runs the UI on a separate Vite server, same host as the API.
	got := auditResultsURL("http://localhost:8080", localdev.ModeDev, devCfg(), "abc")
	want := "http://localhost:23001/audit/abc"
	if got != want {
		t.Fatalf("dev mode must swap to the frontend port\n got: %s\nwant: %s", got, want)
	}
}

func TestRemoteApiIsSameOriginEvenInDevMode(t *testing.T) {
	// A non-loopback backend serves its own SPA; the local vite port is
	// irrelevant to it. Matches the `cli` binary's uiURL() rule — the two
	// disagreed here before, which is how the divergence surfaced.
	got := auditResultsURL("http://10.0.0.5:8080", localdev.ModeDev, devCfg(), "abc")
	want := "http://10.0.0.5:8080/audit/abc"
	if got != want {
		t.Fatalf("a remote backend serves its own UI\n got: %s\nwant: %s", got, want)
	}
}

func TestCredentialsInTheApiUrlAreNotPrinted(t *testing.T) {
	got := auditResultsURL("https://user:secret@vulture.example.com", localdev.ModeInstall, devCfg(), "abc")
	if strings.Contains(got, "secret") || strings.Contains(got, "user:") {
		t.Fatalf("credentials leaked into the printed link: %s", got)
	}
	if got != "https://vulture.example.com/audit/abc" {
		t.Fatalf("got %s", got)
	}
}

func TestFrontendUrlEnvOverridesEverything(t *testing.T) {
	t.Setenv("VULTURE_FRONTEND_URL", "https://ui.example.com/")
	got := auditResultsURL("http://localhost:28080", localdev.ModeInstall, devCfg(), "abc")
	if got != "https://ui.example.com/audit/abc" {
		t.Fatalf("got %s", got)
	}
}

func TestMalformedApiUrlFallsBackWithoutPanicking(t *testing.T) {
	for _, bad := range []string{"", "://nope", "not a url at all"} {
		got := auditResultsURL(bad, localdev.ModeDev, devCfg(), "abc")
		if got == "" {
			t.Fatalf("input %q produced an empty link", bad)
		}
		if got != "http://localhost:23001/audit/abc" {
			t.Fatalf("input %q: unexpected fallback %s", bad, got)
		}
	}
}

func TestAuditIdIsAlwaysPresent(t *testing.T) {
	for _, mode := range []localdev.Mode{localdev.ModeInstall, localdev.ModeDev} {
		got := auditResultsURL("http://localhost:28080", mode, devCfg(), "the-id")
		if got[len(got)-len("/audit/the-id"):] != "/audit/the-id" {
			t.Fatalf("mode %v dropped the audit id: %s", mode, got)
		}
	}
}
