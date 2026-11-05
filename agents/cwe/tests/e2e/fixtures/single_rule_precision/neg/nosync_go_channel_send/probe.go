package probe

import (
	"fmt"
	"time"
)

// within returns probe's answer, or a timeout error once wait has passed.
// The goroutine hands its result over a buffered channel.
func within(probe func() error, wait time.Duration) error {
	answer := make(chan error, 1)
	// EXPECT-NEXT: clean
	go func() { answer <- probe() }()
	select {
	case err := <-answer:
		return err
	case <-time.After(wait):
		return fmt.Errorf("probe timed out after %s", wait)
	}
}
