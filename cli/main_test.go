package main

import "testing"

// TestUIURL pins the "View in UI" link resolution: an explicit
// VULTURE_FRONTEND_URL override wins, otherwise the configured frontend host.
// The UI is served by a separate frontend server (Vite in dev, the frontend
// container in Docker), NOT the backend/API port — pointing at the backend in
// dev mode yields a 404 since it serves the API only.
func TestUIURL(t *testing.T) {
	tests := []struct {
		name        string
		frontendEnv string // VULTURE_FRONTEND_URL ("" = unset)
		want        string
	}{
		{
			name: "no override → configured frontend host",
			want: defaultFrontendURL,
		},
		{
			name:        "explicit VULTURE_FRONTEND_URL wins",
			frontendEnv: "https://ui.example.com",
			want:        "https://ui.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Empty string is treated as unset by uiURL; t.Setenv restores the
			// prior value when the subtest ends.
			t.Setenv("VULTURE_FRONTEND_URL", tc.frontendEnv)
			if got := uiURL(); got != tc.want {
				t.Errorf("uiURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
