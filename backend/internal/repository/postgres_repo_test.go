package repository

import "testing"

func TestFloat32SliceToVec(t *testing.T) {
	tests := []struct {
		input []float32
		want  string
	}{
		{[]float32{0.1, 0.2, 0.3}, "[0.1,0.2,0.3]"},
		{[]float32{1.0}, "[1]"},
		{[]float32{}, "[]"},
		{nil, "[]"},
		{[]float32{-0.5, 0.0, 0.5}, "[-0.5,0,0.5]"},
	}
	for _, tt := range tests {
		got := float32SliceToVec(tt.input)
		if got != tt.want {
			t.Errorf("float32SliceToVec(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewPostgresMemoryRepo_Constructor(t *testing.T) {
	repo := NewPostgresMemoryRepo(nil)
	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
}
