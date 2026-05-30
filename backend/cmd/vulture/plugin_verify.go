package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/vulture/backend/internal/cosign"
	"github.com/vulture/backend/internal/pluginlifecycle"
	"github.com/vulture/backend/pkg/pluginregistry"
)

func cmdPluginVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plugin verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cosignBinary := fs.String("cosign", "", "path to cosign binary")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: vulture plugin verify <name>")
		return 1
	}
	name := fs.Arg(0)
	pluginsDir := resolvePluginsDir()
	pluginDir := filepath.Join(pluginsDir, name)
	manifestPath := filepath.Join(pluginDir, "plugin.toml")
	m, err := pluginregistry.ParseManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "plugin verify: %v\n", err)
		return 1
	}
	if m.Trust.Tier != pluginregistry.TierCommunitySigned {
		fmt.Fprintf(stderr, "plugin verify: %q is tier=%s (only community-signed plugins are cosign-verified)\n",
			name, m.Trust.Tier)
		return 1
	}
	identity := strings.TrimPrefix(m.Trust.Signature, "cosign://")
	bundle := manifestPath + ".sigstore"
	res, err := cosign.Verify(cosign.VerifyOptions{
		BlobPath:            manifestPath,
		BundlePath:          bundle,
		CertificateIdentity: identity,
		CosignBinary:        *cosignBinary,
	})
	if err != nil {
		fmt.Fprintf(stderr, "plugin verify: %v\n", err)
		return 1
	}
	mk := pluginlifecycle.Marker{
		Subject:       identity,
		Signature:     m.Trust.Signature,
		CosignVersion: res.CosignVersion,
	}
	if err := pluginlifecycle.WriteMarker(pluginDir, mk); err != nil {
		fmt.Fprintf(stderr, "plugin verify: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Verified %s (subject=%s)\n", name, identity)
	return 0
}

func cmdPluginInfo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plugin info", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: vulture plugin info <name>")
		return 1
	}
	name := fs.Arg(0)
	pluginsDir := resolvePluginsDir()
	pluginDir := filepath.Join(pluginsDir, name)
	m, err := pluginregistry.ParseManifest(filepath.Join(pluginDir, "plugin.toml"))
	if err != nil {
		fmt.Fprintf(stderr, "plugin info: %v\n", err)
		return 1
	}
	printPluginInfo(stdout, name, m, pluginDir)
	return 0
}

func printPluginInfo(out io.Writer, name string, m pluginregistry.Manifest, pluginDir string) {
	fmt.Fprintf(out, "Name:        %s\n", name)
	fmt.Fprintf(out, "Version:     %s\n", m.Plugin.Version)
	fmt.Fprintf(out, "Publisher:   %s\n", m.Plugin.Publisher)
	fmt.Fprintf(out, "Tier:        %s\n", m.Trust.Tier)
	fmt.Fprintf(out, "Description: %s\n", m.Plugin.Description)
	mk, err := pluginlifecycle.ReadMarker(pluginDir)
	switch {
	case err == nil:
		fmt.Fprintf(out, "Verified:    yes (subject=%s, cosign=%s, at=%s)\n",
			mk.Subject, mk.CosignVersion, mk.VerifiedAt.Format("2006-01-02T15:04:05Z"))
	case errors.Is(err, pluginlifecycle.ErrMarkerNotFound):
		fmt.Fprintln(out, "Verified:    no (marker absent)")
	default:
		fmt.Fprintf(out, "Verified:    error (%v)\n", err)
	}
}
