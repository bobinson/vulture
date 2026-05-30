package pathutil_test

// RED tests for the shared RejectTraversal helper (MINOR #19).
// Used by pluginsupervisor/paths.go (and any future consumer needing
// the same `..` check). Lifted out of the duplicated inline checks in
// pluginregistry and pluginsupervisor.

import (
	"testing"

	"github.com/vulture/backend/internal/pathutil"
)

func TestRejectTraversal_CleanAbsolutePath_OK(t *testing.T) {
	if err := pathutil.RejectTraversal("/etc/passwd"); err != nil {
		t.Errorf("clean path /etc/passwd should pass; got %v", err)
	}
}

func TestRejectTraversal_DotDotInMiddle_Rejected(t *testing.T) {
	if err := pathutil.RejectTraversal("/etc/../etc/passwd"); err == nil {
		t.Errorf("traversal /etc/../etc/passwd must be rejected")
	}
}

func TestRejectTraversal_BareDotDot_Rejected(t *testing.T) {
	if err := pathutil.RejectTraversal(".."); err == nil {
		t.Errorf("bare .. must be rejected")
	}
}

func TestRejectTraversal_RelativeTraversal_Rejected(t *testing.T) {
	if err := pathutil.RejectTraversal("foo/../bar"); err == nil {
		t.Errorf("foo/../bar must be rejected")
	}
}

func TestRejectTraversal_SingleDotComponent_OK(t *testing.T) {
	if err := pathutil.RejectTraversal("foo/./bar"); err != nil {
		t.Errorf("foo/./bar should be permitted (single dot is not traversal); got %v", err)
	}
}

func TestRejectTraversal_TrailingDotDot_Rejected(t *testing.T) {
	if err := pathutil.RejectTraversal("/audit-inputs/.."); err == nil {
		t.Errorf("trailing /.. must be rejected")
	}
}
