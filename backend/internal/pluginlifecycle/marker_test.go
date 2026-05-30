package pluginlifecycle_test

// Tests for the .cosign-verified TOML marker, written into each
// community-signed plugin dir.
//
// AC4 / AC14: marker file is mode 0600, contains verified_at, subject,
// signature, cosign_version fields. Round-trip via ReadMarker / WriteMarker.
// AC: missing marker -> typed ErrMarkerNotFound; malformed TOML -> parse error.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vulture/backend/internal/pluginlifecycle"
)

func TestMarker_WriteReadRoundTrip_AC4(t *testing.T) {
	dir := t.TempDir()
	want := pluginlifecycle.Marker{
		VerifiedAt:    time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Subject:       "sigstore/foo/bar",
		Signature:     "cosign://sigstore/foo/bar",
		CosignVersion: "v9.9.9-mock",
	}
	if err := pluginlifecycle.WriteMarker(dir, want); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	got, err := pluginlifecycle.ReadMarker(dir)
	if err != nil {
		t.Fatalf("ReadMarker: %v", err)
	}
	if !got.VerifiedAt.Equal(want.VerifiedAt) {
		t.Errorf("VerifiedAt got=%v want=%v", got.VerifiedAt, want.VerifiedAt)
	}
	if got.Subject != want.Subject {
		t.Errorf("Subject got=%q want=%q", got.Subject, want.Subject)
	}
	if got.Signature != want.Signature {
		t.Errorf("Signature got=%q want=%q", got.Signature, want.Signature)
	}
	if got.CosignVersion != want.CosignVersion {
		t.Errorf("CosignVersion got=%q want=%q", got.CosignVersion, want.CosignVersion)
	}
}

func TestMarker_WriteFileMode0600_AC14(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes not enforced on Windows")
	}
	dir := t.TempDir()
	if err := pluginlifecycle.WriteMarker(dir, pluginlifecycle.Marker{
		Subject:       "x",
		Signature:     "cosign://x/y",
		CosignVersion: "v1",
		VerifiedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, ".cosign-verified"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("marker mode = 0o%o, want 0o600", mode)
	}
}

func TestMarker_ReadMissingFile_ErrMarkerNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := pluginlifecycle.ReadMarker(dir)
	if err == nil {
		t.Fatalf("expected error for missing marker")
	}
	if !errors.Is(err, pluginlifecycle.ErrMarkerNotFound) {
		t.Errorf("expected ErrMarkerNotFound, got %v", err)
	}
}

func TestMarker_ReadMalformedTOML_ParseError(t *testing.T) {
	dir := t.TempDir()
	// Write garbage that isn't valid TOML.
	if err := os.WriteFile(filepath.Join(dir, ".cosign-verified"),
		[]byte("not [ valid toml ============== \x00garbage"), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	_, err := pluginlifecycle.ReadMarker(dir)
	if err == nil {
		t.Fatalf("expected parse error for tampered marker")
	}
	if errors.Is(err, pluginlifecycle.ErrMarkerNotFound) {
		t.Errorf("tampered file should not be reported as 'not found'")
	}
}
