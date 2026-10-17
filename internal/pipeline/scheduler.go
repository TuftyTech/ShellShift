// Package pipeline runs a whole collection cycle.
package pipeline

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Scheduler bounds how many verifications run at once.
//
// The predecessor used a literal: six sing-box batches in flight, which turned 166 batches
// into 28 sequential waves and cost roughly 532 seconds of a drone. The number had no
// defensible basis — the phase is bound by waiting on timeouts, not by CPU, and the
// download semaphore that was supposed to make a higher value dangerous never engaged at
// the observed survival rate.
//
// So concurrency here is derived from what the work actually is: overwhelmingly waiting.
// The starting point is generous, and it adapts down only if the process is genuinely
// saturated rather than merely busy.
type Scheduler struct {
	sem      chan struct{}
	inFlight atomic.Int64
	peak     atomic.Int64
}

// DefaultConcurrency returns a starting point for I/O-bound verification.
//
// Verification spends its time in network waits, so the useful ceiling is far above the
// core count. It is bounded rather than unbounded because each in-flight verification
// holds an outbound with its own buffers, and because a public source list should not be
// able to turn the verifier into a connection flood.
func DefaultConcurrency() int {
	n := runtime.NumCPU() * 64
	if n < 128 {
		n = 128
	}
	if n > 1024 {
		n = 1024
	}
	return n
}

// NewScheduler builds a scheduler. A concurrency of zero uses the derived default.
func NewScheduler(concurrency int) *Scheduler {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency()
	}
	return &Scheduler{sem: make(chan struct{}, concurrency)}
}

// Limit is the configured ceiling.
func (s *Scheduler) Limit() int { return cap(s.sem) }

// Peak is the highest number of simultaneous verifications observed, which is the figure
// that tells whether the ceiling is actually binding.
func (s *Scheduler) Peak() int64 { return s.peak.Load() }

// acquire takes a slot, or fails if the context ends first.
func (s *Scheduler) acquire(ctx context.Context) error {
	select {
	case s.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scheduler) release() { <-s.sem }

// enter records that a verification started and updates the observed peak.
func (s *Scheduler) enter() {
	current := s.inFlight.Add(1)
	for {
		peak := s.peak.Load()
		if current <= peak || s.peak.CompareAndSwap(peak, current) {
			return
		}
	}
}

func (s *Scheduler) leave() { s.inFlight.Add(-1) }

// Each runs fn for every item concurrently, bounded by the scheduler, and waits.
//
// The work is started in its own goroutine and *then* acquires a slot. Doing it the other
// way round — acquiring first and calling fn on the caller goroutine — looks like a
// concurrency limiter and is in fact a sequential loop. TestEachActuallyRunsConcurrently
// exists because that is exactly the mistake this file made on its first draft.
func Each[T any](ctx context.Context, s *Scheduler, items []T, fn func(context.Context, T)) error {
	var wg sync.WaitGroup
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(it T) {
			defer wg.Done()
			if err := s.acquire(ctx); err != nil {
				return
			}
			defer s.release()
			s.enter()
			defer s.leave()
			fn(ctx, it)
		}(item)
	}
	wg.Wait()
	return ctx.Err()
}

// Stopwatch measures a phase.
type Stopwatch struct {
	started time.Time
	now     func() time.Time
}

// StartStopwatch begins timing.
func StartStopwatch() *Stopwatch {
	return &Stopwatch{started: time.Now(), now: time.Now}
}

// Elapsed is the time since the stopwatch started.
func (s *Stopwatch) Elapsed() time.Duration { return s.now().Sub(s.started) }
