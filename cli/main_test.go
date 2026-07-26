package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedInstall makes dir look like a native install (VERSION file present),
// which is how vhome.IsInstall() recognizes Mode E.
func seedInstall(t *testing.T, dir string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("v1\n"), 0o644); err != nil {
		t.Fatalf("seed VERSION: %v", err)
	}
	return dir
}

// TestUIURL pins "View in UI" link resolution across deployment topologies.
// The web-UI location is a property of the target backend; the CLI infers it as:
//   - VULTURE_FRONTEND_URL override always wins;
//   - a REMOTE backend serves the SPA at the SAME origin as the API (embedded
//     SPA, or a reverse proxy routing "/" to the backend) — never port-swap,
//     preserve any subpath, strip credentials;
//   - a LOOPBACK backend is local: a native install shares the API origin, a
//     dev/Docker stack uses the separate [ports] frontend_host port.
//
// Note: the remote cases assert NO port swap — earlier revisions wrongly forced
// :frontend_host onto remote/proxied hosts (a dead port for Mode B/D servers).
func TestUIURL(t *testing.T) {
	const override = "https://ui.example.com"
	tests := []struct {
		name        string
		frontendEnv string // VULTURE_FRONTEND_URL ("" = unset)
		install     bool   // seed a native install (only consulted for loopback)
		apiURL      string // resolved API base ("" = local default)
		want        string
	}{
		{
			name:   "dev + local default → frontend_host port",
			apiURL: "",
			want:   defaultFrontendURL, // http://localhost:23001
		},
		{
			name:    "install + local default → backend origin",
			install: true,
			apiURL:  "",
			want:    defaultAPIURL, // http://localhost:28080
		},
		{
			name:    "install + remote --server → that origin",
			install: true,
			apiURL:  "https://vulture.example.com",
			want:    "https://vulture.example.com",
		},
		{
			name:   "remote --server (no install) → same origin, NO port swap",
			apiURL: "http://devbox:28080",
			want:   "http://devbox:28080",
		},
		{
			name:   "remote proxied https, no explicit port → same origin",
			apiURL: "https://ci.example.com",
			want:   "https://ci.example.com",
		},
		{
			name:   "remote with trailing slash → normalized",
			apiURL: "https://vulture.example.com/",
			want:   "https://vulture.example.com",
		},
		{
			name:   "remote subpath-mounted proxy → path preserved",
			apiURL: "https://tools.example.com/vulture",
			want:   "https://tools.example.com/vulture",
		},
		{
			name:   "remote IPv6 host → same origin, brackets preserved",
			apiURL: "http://[2001:db8::1]:28080",
			want:   "http://[2001:db8::1]:28080",
		},
		{
			name:   "remote --server with credentials → creds stripped from link",
			apiURL: "http://user:pass@devbox:28080",
			want:   "http://devbox:28080",
		},
		{
			name:   "loopback IPv6 dev → frontend_host port",
			apiURL: "http://[::1]:28080",
			want:   "http://[::1]:23001",
		},
		{
			name:        "override wins for a remote host",
			frontendEnv: override,
			apiURL:      "http://devbox:28080",
			want:        override,
		},
		{
			name:        "override wins in install mode",
			frontendEnv: override,
			install:     true,
			apiURL:      "https://vulture.example.com",
			want:        override,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VULTURE_FRONTEND_URL", tc.frontendEnv)
			// Neutralize any ambient config.ini so frontend_host resolves to the
			// 23001 fallback deterministically.
			t.Setenv("VULTURE_CONFIG", "")
			home := t.TempDir()
			if tc.install {
				seedInstall(t, home)
			}
			t.Setenv("VULTURE_HOME", home) // empty dir (no VERSION) => dev mode
			if got := uiURL(tc.apiURL); got != tc.want {
				t.Errorf("uiURL(%q) = %q, want %q", tc.apiURL, got, tc.want)
			}
		})
	}
}

// --- end-to-end: the printed "View in UI" link actually resolves (no 404) ---

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// extractViewInUI pulls the URL from the "View in UI: <url>" summary line.
// Returns "" (not fatal) when absent, so callers can assert its absence too.
func findViewInUI(out string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if u, ok := strings.CutPrefix(line, "View in UI:"); ok {
			return strings.TrimSpace(u)
		}
	}
	return ""
}

func extractViewInUI(t *testing.T, out string) string {
	t.Helper()
	if u := findViewInUI(out); u != "" {
		return u
	}
	t.Fatalf("no 'View in UI:' line in output:\n%s", out)
	return ""
}

// assertGet200 fetches link (using client, or the default client if nil) and
// fails unless it returns 200 — proving the link the user would click resolves.
func assertGet200(t *testing.T, client *http.Client, link string) {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(link)
	if err != nil {
		t.Fatalf("GET %s: %v", link, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200 (link would 404 for the user)", link, resp.StatusCode)
	}
}

// spaHandler serves a fake SPA at /audit/* and 404s everything else — mimicking
// a server that serves the web UI.
func spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/audit/") {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<!doctype html><title>Vulture</title>")
			return
		}
		http.NotFound(w, r)
	})
}

// TestE2E_InstallModeLinkReachable: a native install serves BOTH the audit API
// and the SPA on ONE origin. The printed link must sit on that origin and 200.
func TestE2E_InstallModeLinkReachable(t *testing.T) {
	srv := httptest.NewServer(spaHandler())
	defer srv.Close()

	t.Setenv("VULTURE_FRONTEND_URL", "")
	t.Setenv("VULTURE_CONFIG", "")
	t.Setenv("VULTURE_HOME", seedInstall(t, t.TempDir()))

	out := captureStdout(t, func() {
		printAuditSummary(audit{ID: "abc123", Status: "completed"}, srv.URL)
	})
	link := extractViewInUI(t, out)
	if !strings.HasPrefix(link, srv.URL+"/audit/") {
		t.Fatalf("install-mode link %q not on API origin %q", link, srv.URL)
	}
	assertGet200(t, nil, link)
}

// TestE2E_InstallModeHTTPSReachable: same-origin resolution must preserve the
// https scheme end-to-end and resolve against a TLS server.
func TestE2E_InstallModeHTTPSReachable(t *testing.T) {
	srv := httptest.NewTLSServer(spaHandler())
	defer srv.Close()

	t.Setenv("VULTURE_FRONTEND_URL", "")
	t.Setenv("VULTURE_CONFIG", "")
	t.Setenv("VULTURE_HOME", seedInstall(t, t.TempDir()))

	out := captureStdout(t, func() {
		printAuditSummary(audit{ID: "tls1", Status: "completed"}, srv.URL)
	})
	link := extractViewInUI(t, out)
	if !strings.HasPrefix(link, "https://") {
		t.Fatalf("https not preserved: link=%q", link)
	}
	assertGet200(t, srv.Client(), link) // srv.Client() trusts the test cert
}

// TestE2E_DevModeLinkReachable: a dev/Docker split serves the SPA on a SEPARATE
// local server (frontend_host port). The link must carry the API host but the
// frontend port, must NOT point at the API origin, and must resolve.
func TestE2E_DevModeLinkReachable(t *testing.T) {
	api := httptest.NewServer(http.NotFoundHandler()) // API only; SPA 404s here
	defer api.Close()
	frontend := httptest.NewServer(spaHandler())
	defer frontend.Close()

	fu, _ := url.Parse(frontend.URL)
	cfg := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(cfg, []byte("[ports]\nfrontend_host="+fu.Port()+"\n"), 0o644); err != nil {
		t.Fatalf("write config.ini: %v", err)
	}
	t.Setenv("VULTURE_CONFIG", cfg)
	t.Setenv("VULTURE_FRONTEND_URL", "")
	t.Setenv("VULTURE_HOME", t.TempDir()) // no VERSION => dev mode

	out := captureStdout(t, func() {
		printAuditSummary(audit{ID: "xyz789", Status: "completed"}, api.URL)
	})
	link := extractViewInUI(t, out)
	if strings.HasPrefix(link, api.URL+"/") {
		t.Fatalf("dev-mode link %q wrongly points at API origin (would 404)", link)
	}
	if !strings.HasPrefix(link, frontend.URL+"/audit/") {
		t.Fatalf("dev-mode link %q not on frontend origin %q", link, frontend.URL)
	}
	assertGet200(t, nil, link)
}

// TestE2E_FrontendURLOverrideReachable: the override wins over mode detection
// and points at a wholly separate UI host that must resolve.
func TestE2E_FrontendURLOverrideReachable(t *testing.T) {
	ui := httptest.NewServer(spaHandler())
	defer ui.Close()
	api := httptest.NewServer(http.NotFoundHandler())
	defer api.Close()

	t.Setenv("VULTURE_CONFIG", "")
	t.Setenv("VULTURE_FRONTEND_URL", ui.URL)
	t.Setenv("VULTURE_HOME", seedInstall(t, t.TempDir())) // even in install mode, override wins

	out := captureStdout(t, func() {
		printAuditSummary(audit{ID: "ovr1", Status: "completed"}, api.URL)
	})
	link := extractViewInUI(t, out)
	if !strings.HasPrefix(link, ui.URL+"/audit/") {
		t.Fatalf("override link %q not on override origin %q", link, ui.URL)
	}
	assertGet200(t, nil, link)
}

// TestE2E_OutputResultThreadsAPIURL exercises the outputResult wrapper (the path
// cmdScan/cmdProve/discover use) end-to-end: text mode prints a reachable link
// derived from the passed apiURL; json mode prints machine output with no link.
func TestE2E_OutputResultThreadsAPIURL(t *testing.T) {
	srv := httptest.NewServer(spaHandler())
	defer srv.Close()
	t.Setenv("VULTURE_FRONTEND_URL", "")
	t.Setenv("VULTURE_CONFIG", "")
	t.Setenv("VULTURE_HOME", seedInstall(t, t.TempDir()))
	a := audit{ID: "res1", Status: "completed"}

	textOut := captureStdout(t, func() { outputResult(a, ciFlags{output: "text"}, srv.URL) })
	link := extractViewInUI(t, textOut)
	if !strings.HasPrefix(link, srv.URL+"/audit/") {
		t.Fatalf("outputResult text link %q not on API origin %q", link, srv.URL)
	}
	assertGet200(t, nil, link)

	jsonOut := captureStdout(t, func() { outputResult(a, ciFlags{output: "json"}, srv.URL) })
	if l := findViewInUI(jsonOut); l != "" {
		t.Fatalf("json output should not print a UI link, got %q", l)
	}
	if !strings.Contains(jsonOut, "\"res1\"") {
		t.Fatalf("json output missing audit id:\n%s", jsonOut)
	}
}
