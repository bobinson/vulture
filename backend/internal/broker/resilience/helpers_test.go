package resilience

import (
	"context"
	"errors"
	"sync"
	"time"
)

// fakeClock is a deterministic, controllable Clock for tests. Sleep does NOT
// block on wall time: it advances a logical timer set that the test drives
// via Advance. Sleepers waiting on a duration release once virtual time
// reaches their wake instant, or immediately with ctx.Err() on cancel.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*sleepWaiter
}

type sleepWaiter struct {
	wakeAt time.Time
	ch     chan struct{}
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(0, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Sleep blocks until virtual time advances by d, or ctx is done.
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}
	c.mu.Lock()
	w := &sleepWaiter{wakeAt: c.now.Add(d), ch: make(chan struct{})}
	c.waiters = append(c.waiters, w)
	c.mu.Unlock()

	select {
	case <-w.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Advance moves virtual time forward and wakes any due sleepers.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var remaining []*sleepWaiter
	for _, w := range c.waiters {
		if !w.wakeAt.After(c.now) {
			close(w.ch)
		} else {
			remaining = append(remaining, w)
		}
	}
	c.waiters = remaining
	c.mu.Unlock()
}

// pendingSleepers reports how many sleepers are currently waiting.
func (c *fakeClock) pendingSleepers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// identityJitter returns the backoff unchanged (deterministic; no randomness).
func identityJitter(d time.Duration) time.Duration { return d }

// classifierFunc adapts a func to RetryClassifier.
type classifierFunc func(err error) (bool, time.Duration)

func (f classifierFunc) Retryable(err error) (bool, time.Duration) { return f(err) }

// Test error taxonomy: these stand in for conn/429/5xx (retryable) vs a
// terminal 4xx / auth error (not retryable).
var (
	errConn       = errors.New("connection refused")
	err429        = errors.New("429 too many requests")
	err500        = errors.New("500 internal server error")
	errBadRequest = errors.New("400 invalid_request") // not retryable
)

// defaultClassifier retries conn/429/5xx; err429 carries a Retry-After hint.
func defaultClassifier() RetryClassifier {
	return classifierFunc(func(err error) (bool, time.Duration) {
		switch {
		case errors.Is(err, err429):
			return true, 250 * time.Millisecond
		case errors.Is(err, errConn), errors.Is(err, err500):
			return true, 0
		default:
			return false, 0
		}
	})
}

// scriptedCall returns a Call that yields errs in order, then nil forever.
// It records how many times it was invoked.
type scriptedCall struct {
	mu    sync.Mutex
	errs  []error
	calls int
}

func newScriptedCall(errs ...error) *scriptedCall { return &scriptedCall{errs: errs} }

func (s *scriptedCall) fn() Call {
	return func(ctx context.Context) error {
		s.mu.Lock()
		i := s.calls
		s.calls++
		s.mu.Unlock()
		if i < len(s.errs) {
			return s.errs[i]
		}
		return nil
	}
}

func (s *scriptedCall) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}
