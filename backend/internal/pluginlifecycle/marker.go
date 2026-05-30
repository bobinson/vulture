package pluginlifecycle

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// MarkerFilename is the per-plugin file name for the cosign-verified
// marker. Convention from LLD D3 / D5.
const MarkerFilename = ".cosign-verified"

// Marker records the cosign-verified status of a community-signed
// plugin. Absence of the file == unverified (LLD D5 convention).
type Marker struct {
	VerifiedAt    time.Time `toml:"verified_at"`
	Subject       string    `toml:"subject"`
	Signature     string    `toml:"signature"`
	CosignVersion string    `toml:"cosign_version"`
}

// ErrMarkerNotFound signals a missing marker file (vs. a parse error).
// Callers check via errors.Is so they can distinguish "never verified"
// from "marker tampered with".
var ErrMarkerNotFound = errors.New("cosign marker not found")

// WriteMarker writes m into <pluginDir>/.cosign-verified atomically
// at mode pluginregistry.MarkerMode.
func WriteMarker(pluginDir string, m Marker) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return fmt.Errorf("encode marker: %w", err)
	}
	path := filepath.Join(pluginDir, MarkerFilename)
	return writeFileAtomic(path, buf.Bytes(), pluginregistry.MarkerMode)
}

// ReadMarker parses <pluginDir>/.cosign-verified. Returns
// ErrMarkerNotFound if the file does not exist.
func ReadMarker(pluginDir string) (Marker, error) {
	path := filepath.Join(pluginDir, MarkerFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Marker{}, ErrMarkerNotFound
		}
		return Marker{}, fmt.Errorf("read marker: %w", err)
	}
	var m Marker
	if _, err := toml.Decode(string(data), &m); err != nil {
		return Marker{}, fmt.Errorf("decode marker: %w", err)
	}
	return m, nil
}
