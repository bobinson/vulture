package gitutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/vulture/backend/internal/config"
)

// EnsureSSHStrictCompat is the 0065 §L2 startup gate. The default
// StrictHostKeyChecking=accept-new requires OpenSSH >= 7.6. It probes the
// installed ssh via `ssh -V`; if the version is older than 7.6 while strict is
// still the accept-new default, it forces VULTURE_GIT_SSH_STRICT=yes semantics
// (which still verifies once the persistent known_hosts is populated) and
// returns a prominent warning string. Returns "" when no adjustment is needed
// or when the probe is not applicable (insecure rollback flag set, or strict
// explicitly overridden to a non-accept-new value).
func EnsureSSHStrictCompat(ctx context.Context, setenv func(string, string) error) string {
	if config.EnvTruthy("VULTURE_GIT_SSH_INSECURE") {
		return "" // legacy no-verification rollback; nothing to gate
	}
	if strict := sshStrictMode(); strict != "accept-new" {
		return "" // operator picked an explicit mode; respect it
	}
	out, err := exec.CommandContext(ctx, "ssh", "-V").CombinedOutput()
	if err != nil {
		return "" // ssh not probeable; leave default (fails safe at clone time)
	}
	major, minor, ok := parseOpenSSHVersion(string(out))
	if !ok {
		return ""
	}
	if major > 7 || (major == 7 && minor >= 6) {
		return "" // accept-new supported
	}
	_ = setenv("VULTURE_GIT_SSH_STRICT", "yes")
	return fmt.Sprintf("WARNING (0065): OpenSSH %d.%d < 7.6 does not support "+
		"StrictHostKeyChecking=accept-new; forcing strict=yes behind the "+
		"persistent known_hosts. Upgrade OpenSSH or set VULTURE_GIT_SSH_KNOWN_HOSTS.",
		major, minor)
}

func sshStrictMode() string {
	if v := strings.TrimSpace(os.Getenv("VULTURE_GIT_SSH_STRICT")); v != "" {
		return v
	}
	return "accept-new"
}

// parseOpenSSHVersion extracts the major.minor from an `ssh -V` banner such as
// "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4, OpenSSL 3.0.2 15 Mar 2022".
func parseOpenSSHVersion(banner string) (major, minor int, ok bool) {
	const marker = "OpenSSH_"
	i := strings.Index(banner, marker)
	if i < 0 {
		return 0, 0, false
	}
	rest := banner[i+len(marker):]
	// version token ends at the first char that is not a digit or '.'
	end := 0
	for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
		end++
	}
	parts := strings.SplitN(rest[:end], ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}
