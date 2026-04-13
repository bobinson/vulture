package handler

import (
	"testing"
)

func TestExtractPipelineID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/pipelines/abc-123", "abc-123"},
		{"/api/pipelines/abc-123/stream", "abc-123"},
		{"/api/pipelines/", ""},
		{"/api/pipelines", ""},
	}
	for _, tt := range tests {
		got := extractPipelineID(tt.path)
		if got != tt.want {
			t.Errorf("extractPipelineID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
