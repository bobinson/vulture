package gitutil

import (
	"context"
	"fmt"
	"os/exec"
)

func Clone(ctx context.Context, url, destPath string, depth int) error {
	args := []string{"clone"}
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}
	args = append(args, url, destPath)
	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone: %s: %w", string(output), err)
	}
	return nil
}
