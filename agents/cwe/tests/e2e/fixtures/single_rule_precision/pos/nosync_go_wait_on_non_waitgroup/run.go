package run

import (
	"context"
	"os/exec"
)

// start waits for a command in the background and writes the result to a
// captured variable; exec.Cmd.Wait is not a WaitGroup and orders nothing.
func start(cmd *exec.Cmd) error {
	var lastErr error
	// EXPECT-NEXT: finding
	go func() { lastErr = cmd.Wait() }()
	return lastErr
}

// tick bumps a captured counter; reading ctx.Done() synchronises nothing.
func tick(ctx context.Context) int {
	counter := 0
	// EXPECT-NEXT: finding
	go func() { counter++; _ = ctx.Done() }()
	return counter
}
