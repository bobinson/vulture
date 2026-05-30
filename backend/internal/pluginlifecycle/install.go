package pluginlifecycle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulture/backend/internal/cosign"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// InstallOptions configures one Install call. Pinned by LLD AC2/AC3.
type InstallOptions struct {
	SourcePath   string
	PluginsDir   string
	StatePath    string
	AssumeYes    bool
	In           io.Reader
	Out          io.Writer
	CosignBinary string
	Now          func() time.Time
	SaveStateFn  func(string, pluginregistry.StateFile) error
}

// InstallResult summarises a completed install.
type InstallResult struct {
	PluginName string
	PluginPath string
	MarkerPath string
	Verified   bool
}

// cosignPrefix is the literal scheme prefix on TrustBlock.Signature
// (e.g. "cosign://sigstore/foo/bar"). The part after the prefix is
// passed verbatim to cosign as --certificate-identity (BLOCKER 2).
const cosignPrefix = "cosign://"

// Install copies a plugin manifest into ~/.vulture/plugins/<name>/
// applying cosign verification and ack-prompt flows where the trust
// tier requires it.
func Install(opts InstallOptions) (*InstallResult, error) {
	prepared, err := prepareInstall(opts)
	if err != nil {
		return nil, err
	}
	release, err := AcquireInstallLock(opts.PluginsDir)
	if err != nil {
		return nil, fmt.Errorf("acquire install lock: %w", err)
	}
	defer release()
	return commitInstall(opts, prepared)
}

// preparedInstall holds parsed + validated state ready to commit to disk.
type preparedInstall struct {
	Manifest      pluginregistry.Manifest
	ManifestBytes []byte
	SourceDir     string
	SourceFile    string
}

// prepareInstall handles all pre-lock validation: source resolution,
// symlink rejection, manifest parsing, tier veto.
func prepareInstall(opts InstallOptions) (*preparedInstall, error) {
	if opts.SourcePath == "" {
		return nil, errors.New("install: SourcePath required")
	}
	abs, err := filepath.Abs(opts.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("install: abs path: %w", err)
	}
	manifestFile, err := resolveManifestFile(abs)
	if err != nil {
		return nil, err
	}
	if err := pluginregistry.RejectSymlink(manifestFile); err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	data, err := os.ReadFile(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("install: read manifest: %w", err)
	}
	m, err := pluginregistry.ParseManifestBytes(data, manifestFile)
	if err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	if m.Trust.Tier == pluginregistry.TierInTree {
		return nil, errors.New("install: in-tree plugins are bundled with the backend, not installable")
	}
	return &preparedInstall{
		Manifest:      m,
		ManifestBytes: data,
		SourceDir:     filepath.Dir(manifestFile),
		SourceFile:    manifestFile,
	}, nil
}

// resolveManifestFile accepts either a plugin.toml file or a directory
// containing one. Returns the absolute file path.
func resolveManifestFile(abs string) (string, error) {
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("install: stat source: %w", err)
	}
	// A symlinked dir/file is rejected later by RejectSymlink on the
	// final resolved file path.
	if info.Mode()&os.ModeSymlink != 0 {
		return abs, nil
	}
	if info.IsDir() {
		return filepath.Join(abs, "plugin.toml"), nil
	}
	return abs, nil
}

// commitInstall runs verification, ack flow, then writes plugin dir,
// marker, and state.toml in that order (LLD D5).
func commitInstall(opts InstallOptions, p *preparedInstall) (*InstallResult, error) {
	destDir := filepath.Join(opts.PluginsDir, p.Manifest.Plugin.Name)
	if err := refuseIfAlreadyInstalled(destDir); err != nil {
		return nil, err
	}
	marker, err := verifyIfRequired(opts, p)
	if err != nil {
		return nil, err
	}
	acks := p.Manifest.Trust.RequiredAck
	if err := runAckFlow(opts, acks); err != nil {
		return nil, err
	}
	if err := writePluginFiles(destDir, p.ManifestBytes); err != nil {
		return nil, err
	}
	markerPath := ""
	if marker != nil {
		if err := WriteMarker(destDir, *marker); err != nil {
			return nil, fmt.Errorf("install: write marker: %w", err)
		}
		markerPath = filepath.Join(destDir, MarkerFilename)
	}
	if err := updateStateFile(opts, p, acks); err != nil {
		return nil, err
	}
	return &InstallResult{
		PluginName: p.Manifest.Plugin.Name,
		PluginPath: filepath.Join(destDir, "plugin.toml"),
		MarkerPath: markerPath,
		Verified:   marker != nil,
	}, nil
}

// refuseIfAlreadyInstalled returns a clear error if destDir already
// exists. MAJOR 5: no --force in v1.
func refuseIfAlreadyInstalled(destDir string) error {
	if _, err := os.Stat(destDir); err == nil {
		return fmt.Errorf("install: %q already installed; remove first via `vulture plugin remove`", filepath.Base(destDir))
	}
	return nil
}

// verifyIfRequired runs cosign for community-signed manifests and
// returns the marker contents to persist. Returns nil marker for
// user-supplied tier.
func verifyIfRequired(opts InstallOptions, p *preparedInstall) (*Marker, error) {
	if p.Manifest.Trust.Tier != pluginregistry.TierCommunitySigned {
		return nil, nil
	}
	bundlePath := p.SourceFile + ".sigstore"
	if _, err := os.Stat(bundlePath); err != nil {
		return nil, fmt.Errorf("install: signature bundle not found at %s", bundlePath)
	}
	identity := strings.TrimPrefix(p.Manifest.Trust.Signature, cosignPrefix)
	res, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:            p.SourceFile,
		BundlePath:          bundlePath,
		CertificateIdentity: identity,
		CosignBinary:        opts.CosignBinary,
	})
	if err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	now := nowOrDefault(opts.Now)
	return &Marker{
		VerifiedAt:    now,
		Subject:       identity,
		Signature:     p.Manifest.Trust.Signature,
		CosignVersion: res.CosignVersion,
	}, nil
}

// runAckFlow prints / prompts for required acks. AssumeYes prints only.
func runAckFlow(opts InstallOptions, acks []string) error {
	if len(acks) == 0 {
		return nil
	}
	if opts.AssumeYes {
		return printAcksNonInteractive(opts.Out, acks)
	}
	if opts.In == nil {
		return errors.New("install: interactive prompt needed; pass --yes to confirm non-interactively")
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	return PromptAcks(acks, opts.In, out)
}

func printAcksNonInteractive(out io.Writer, acks []string) error {
	if out == nil {
		return nil
	}
	if _, err := fmt.Fprintln(out, "Recording acknowledgements (--yes mode):"); err != nil {
		return err
	}
	for _, a := range acks {
		if _, err := fmt.Fprintf(out, "  - %s\n", a); err != nil {
			return err
		}
	}
	return nil
}

// writePluginFiles creates the per-plugin dir and writes plugin.toml.
func writePluginFiles(destDir string, manifestBytes []byte) error {
	if err := os.MkdirAll(destDir, pluginregistry.PluginDirMode); err != nil {
		return fmt.Errorf("install: mkdir plugin dir: %w", err)
	}
	if err := os.Chmod(destDir, pluginregistry.PluginDirMode); err != nil {
		return fmt.Errorf("install: chmod plugin dir: %w", err)
	}
	dest := filepath.Join(destDir, "plugin.toml")
	if err := writeFileAtomic(dest, manifestBytes, pluginregistry.ManifestMode); err != nil {
		return fmt.Errorf("install: write plugin.toml: %w", err)
	}
	return nil
}

// updateStateFile merges the new plugin into state.toml via the
// injected SaveStateFn (or pluginregistry.SaveState by default).
func updateStateFile(opts InstallOptions, p *preparedInstall, acks []string) error {
	state, err := pluginregistry.LoadState(opts.StatePath)
	if err != nil {
		return fmt.Errorf("install: load state: %w", err)
	}
	if state.Plugins == nil {
		state.Plugins = map[string]pluginregistry.PluginState{}
	}
	now := nowOrDefault(opts.Now)
	state.Plugins[p.Manifest.Plugin.Name] = pluginregistry.PluginState{
		Enabled:     true,
		TrustAcks:   append([]string{}, acks...),
		InstalledAt: now,
	}
	save := opts.SaveStateFn
	if save == nil {
		save = pluginregistry.SaveState
	}
	if err := save(opts.StatePath, state); err != nil {
		return fmt.Errorf("install: save state: %w", err)
	}
	return nil
}

func nowOrDefault(now func() time.Time) time.Time {
	if now == nil {
		return time.Now().UTC()
	}
	return now()
}
