package handler

import (
	"testing"
)

func TestExtractDiscoverAuditID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/audits/abc-123/discover-result", "abc-123"},
		{"/api/audits//discover-result", ""},
	}
	for _, tt := range tests {
		got := extractDiscoverAuditID(tt.path)
		if got != tt.want {
			t.Errorf("extractDiscoverAuditID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
