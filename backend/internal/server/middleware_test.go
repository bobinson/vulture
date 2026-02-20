package server

import "testing"

func TestIsStreamPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/api/audits/abc/stream", true},
		{"/api/audits/abc", false},
		{"/api/audits/", false},
		{"/stream", true},
	}
	for _, tc := range tests {
		got := isStreamPath(tc.path)
		if got != tc.want {
			t.Errorf("isStreamPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
