package service

import (
	"errors"
	"fmt"
	"testing"

	"github.com/vulture/backend/pkg/errkind"
	"github.com/vulture/backend/pkg/gitutil"
)

// TestClassifyCloneErr_HostKeyStoreIs500: a refused SSH host-key store is a
// server fault, not the caller's. However gitutil marks or wraps
// ErrHostKeyStore, classifyCloneErr leaves it unmarked, so the handler answers
// the generic 500, and the cause (store path, reason, remedy) stays whole for
// the log, still of kind ErrHostKeyStore.
func TestClassifyCloneErr_HostKeyStoreIs500(t *testing.T) {
	cause := errors.New("ssh host-key store refused: /data/ssh: is a symlink; set VULTURE_GIT_SSH_KNOWN_HOSTS to an operator-managed known_hosts file")
	for name, in := range map[string]error{
		"marked":  errkind.Mark(gitutil.ErrHostKeyStore, cause),
		"wrapped": fmt.Errorf("%w: /data/ssh: is a symlink", gitutil.ErrHostKeyStore),
	} {
		out := classifyCloneErr(in)
		wantClassified(t, name, in, out, callerMsg{})
		wantUnmarkedClone(t, in, out)
		wantErrsIs(t, out, gitutil.ErrHostKeyStore)
	}
}
