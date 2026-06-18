package pluginsupervisor

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vulture/backend/internal/pathutil"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// readPathWhitelist enumerates the directory prefixes a plugin may
// declare in runtime.fs.read. Prefix match: `/audit-inputs/foo` is
// allowed under `/audit-inputs`.
var readPathWhitelist = []string{
	"/audit-inputs",
	"/src",
	"/workspace",
}

// writePathStaticWhitelist enumerates directory prefixes a plugin may
// write to. The per-plugin `/<plugin-name>-data` is added dynamically
// because it embeds the manifest name.
var writePathStaticWhitelist = []string{
	"/tmp",
	"/var/cache",
	"/var/run",
}

// Options configures both the Supervisor and the argv builder. Fields
// not relevant to argv generation (e.g. DaemonPingInterval) are
// ignored by BuildDockerRunArgv.
type Options struct {
	DockerBinary string
	Network      string
	AuditsDir    string
	// LocalMode mirrors VULTURE_LOCAL_MODE: when true the backend runs
	// on the host (native launcher), so the supervisor's health probe
	// dials host-network plugins at localhost rather than the compose
	// DNS alias (Feature 0055).
	LocalMode          bool
	Logger             interface{ Printf(string, ...any) }
	DaemonPingInterval time.Duration
	Tunables           *Tunables
}

// BuildDockerRunArgv generates the docker run argv (sans the leading
// "docker" binary path) for a container-runtime plugin. The contract
// is pinned by the LLD section "Docker argv contract" and AC #14.
//
// The function is intentionally a thin composition of helper builders:
// each builder owns one orthogonal aspect of the argv (network, fs,
// env, resources) so cyclomatic complexity stays well below the limit.
func BuildDockerRunArgv(plug pluginregistry.Plugin, opts Options) ([]string, error) {
	r := plug.Manifest.Runtime
	if r.Type != pluginregistry.RuntimeContainer {
		return nil, fmt.Errorf("plugin %s: runtime.type=%q is not container", plug.Name(), r.Type)
	}
	alias := pluginregistry.SanitiseDNSName(plug.Name())
	argv := []string{"run", "-d", "--name", "vulture-agent-" + alias}
	if opts.LocalMode {
		// Native launcher: the source is bind-mounted from the host user's
		// tree, often under a 0750 home dir the image's default `nobody`
		// user cannot traverse. Run as the host uid:gid — exactly the
		// access the user already has — so the plugin can read the source.
		// Compose mode keeps the image's hardened default user (the source
		// lives in a shared volume nobody can read). Feature 0055.
		argv = append(argv, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()))
	}

	for _, builder := range argvBuilders(plug, opts, alias) {
		fragment, err := builder()
		if err != nil {
			return nil, err
		}
		argv = append(argv, fragment...)
	}
	if r.Port > 0 {
		argv = append(argv, "-p", fmt.Sprintf("%d", r.Port))
	}
	argv = append(argv, r.Image)
	return argv, nil
}

// argvBuilders returns the per-aspect argv builders in the order they
// must appear in the final argv. Each builder is a closure so it
// shares plug/opts/alias without ceremony at the call site.
func argvBuilders(plug pluginregistry.Plugin, opts Options, alias string) []func() ([]string, error) {
	return []func() ([]string, error){
		func() ([]string, error) { return buildNetworkArgs(plug, opts, alias) },
		func() ([]string, error) { return buildRestartArgs(plug), nil },
		func() ([]string, error) { return buildResourceArgs(plug), nil },
		func() ([]string, error) { return buildFSArgs(plug, opts) },
		func() ([]string, error) { return buildEnvArgs(plug) },
	}
}

func buildRestartArgs(plug pluginregistry.Plugin) []string {
	return []string{"--restart", mapRestartPolicy(plug.Manifest.Runtime.Restart)}
}

func buildResourceArgs(plug pluginregistry.Plugin) []string {
	out := []string{}
	if res, ok := getStringFromAny(plug.Manifest.Runtime.Resources, "cpu"); ok && res != "" {
		out = append(out, "--cpus", res)
	}
	if res, ok := getStringFromAny(plug.Manifest.Runtime.Resources, "memory"); ok && res != "" {
		out = append(out, "--memory", res)
	}
	return out
}

// mapRestartPolicy converts the manifest restart string to the docker
// `--restart` value (LLD "Restart policy mapping" table).
func mapRestartPolicy(manifest string) string {
	switch manifest {
	case "on-failure":
		return "on-failure:5"
	case "always":
		return "always"
	case "unless-stopped":
		return "unless-stopped"
	default:
		return "no"
	}
}

// buildNetworkArgs handles --network and --network-alias selection.
// network=host is rejected unless the manifest declares the
// host-network ack (MAJOR #8).
func buildNetworkArgs(plug pluginregistry.Plugin, opts Options, alias string) ([]string, error) {
	r := plug.Manifest.Runtime
	switch r.Network {
	case "host":
		if !hasAck(plug, "host-network") {
			return nil, fmt.Errorf("plugin %s: runtime.network=host requires host-network ack", plug.Name())
		}
		return []string{"--network", "host"}, nil
	case "none":
		return []string{"--network", "none"}, nil
	default:
		net := opts.Network
		if net == "" {
			net = "vulture"
		}
		return []string{
			"--network", net,
			"--network-alias", pluginregistry.NetworkAliasPrefix + alias,
		}, nil
	}
}

func hasAck(plug pluginregistry.Plugin, want string) bool {
	for _, a := range plug.Manifest.Trust.RequiredAck {
		if a == want {
			return true
		}
	}
	return false
}

// buildFSArgs returns the -v flags for runtime.fs.read (RO) and
// runtime.fs.write (named volumes).
func buildFSArgs(plug pluginregistry.Plugin, opts Options) ([]string, error) {
	r := plug.Manifest.Runtime
	out := []string{}
	readPaths := toStringSlice(r.FS, "read")
	writePaths := toStringSlice(r.FS, "write")
	for _, p := range readPaths {
		if err := validateReadPath(p); err != nil {
			return nil, err
		}
		// Native launcher (LocalMode): the backend references sources by
		// their real host path (local-dir scans, /tmp git clones), which
		// are NOT staged into AuditsDir. Mount host / read-only so any
		// host path resolves under the plugin's audit-inputs mount; the
		// stream dispatch prefixes source_path to match (Feature 0055).
		// docker-compose keeps the staged AuditsDir volume.
		src := opts.AuditsDir
		if opts.LocalMode {
			src = "/"
		}
		out = append(out, "-v", fmt.Sprintf("%s:%s:ro", src, p))
	}
	for _, p := range writePaths {
		if err := validateWritePath(p, plug.Name()); err != nil {
			return nil, err
		}
		vol := volumeNameForWritePath(plug.Name(), p)
		out = append(out, "-v", fmt.Sprintf("%s:%s", vol, p))
	}
	return out, nil
}

func validateReadPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("runtime.fs.read %q: must be absolute path", p)
	}
	if err := pathutil.RejectTraversal(p); err != nil {
		return fmt.Errorf("runtime.fs.read: %w", err)
	}
	if !prefixMatch(p, readPathWhitelist) {
		return fmt.Errorf("runtime.fs.read %q: not in whitelist %v", p, readPathWhitelist)
	}
	return nil
}

func validateWritePath(p, pluginName string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("runtime.fs.write %q: must be absolute path", p)
	}
	if err := pathutil.RejectTraversal(p); err != nil {
		return fmt.Errorf("runtime.fs.write: %w", err)
	}
	wl := append([]string(nil), writePathStaticWhitelist...)
	wl = append(wl, "/"+pluginName+"-data")
	if !prefixMatch(p, wl) {
		return fmt.Errorf("runtime.fs.write %q: not in whitelist %v", p, wl)
	}
	return nil
}

// prefixMatch returns true if `p` equals one of the whitelist entries
// or has it as a `/`-terminated prefix. `/tmpfoo` does NOT match `/tmp`
// (no trailing slash). MAJOR #10.
func prefixMatch(p string, whitelist []string) bool {
	for _, w := range whitelist {
		if p == w {
			return true
		}
		if strings.HasPrefix(p, w+"/") {
			return true
		}
	}
	return false
}

// volumeNameForWritePath builds the docker named-volume identifier:
// vulture-plugin-<plugin-name>-<sanitised-path>.
func volumeNameForWritePath(pluginName, p string) string {
	slug := strings.TrimPrefix(p, "/")
	slug = strings.ReplaceAll(slug, "/", "-")
	return fmt.Sprintf("vulture-plugin-%s-%s", pluginName, slug)
}

// buildEnvArgs emits `-e VAR` flags only for declared envs (required +
// optional) present in the host environment. Required envs missing
// from the host cause a hard error.
func buildEnvArgs(plug pluginregistry.Plugin) ([]string, error) {
	r := plug.Manifest.Runtime
	required := toStringSlice(r.Env, "required")
	optional := toStringSlice(r.Env, "optional")
	// Container images run as a non-root user (e.g. nobody, uid 65534)
	// with no home directory, so CLI tools that write a per-user config/
	// cache dir — semgrep's ~/.semgrep → /.semgrep — crash with EACCES.
	// Default HOME to a writable path. A manifest-declared HOME (appended
	// below from the host env) takes precedence via docker's last-wins
	// rule (Feature 0055).
	out := []string{"-e", "HOME=/tmp"}
	for _, name := range required {
		if _, ok := os.LookupEnv(name); !ok {
			return nil, fmt.Errorf("plugin %s: required env %s not set", plug.Name(), name)
		}
		out = append(out, "-e", name)
	}
	for _, name := range optional {
		if _, ok := os.LookupEnv(name); ok {
			out = append(out, "-e", name)
		}
	}
	return out, nil
}

// toStringSlice coerces an `interface{}`-typed TOML list to []string.
// Used for the `fs.read|write` and `env.required|optional` keys which
// the TOML decoder lands as `[]any`.
func toStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	raw, ok := m[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func getStringFromAny(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	raw, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

