package pipeline

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// This test exists because the first draft of Each acquired a slot and then called the
// work on the caller goroutine, which looks like a concurrency limiter and is a sequential
// loop. A comment would not have caught it.
func TestEachActuallyRunsConcurrently(t *testing.T) {
	const items = 32
	s := NewScheduler(items)

	var running atomic.Int64
	var maxRunning atomic.Int64

	work := make([]int, items)
	err := Each(context.Background(), s, work, func(context.Context, int) {
		n := running.Add(1)
		for {
			m := maxRunning.Load()
			if n <= m || maxRunning.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
	})
	if err != nil {
		t.Fatalf("each: %v", err)
	}
	if maxRunning.Load() < 2 {
		t.Fatalf("peak concurrency was %d: the work ran sequentially", maxRunning.Load())
	}
}

// The ceiling must actually bind.
func TestConcurrencyLimitIsRespected(t *testing.T) {
	const limit = 4
	s := NewScheduler(limit)

	var running atomic.Int64
	var maxRunning atomic.Int64

	work := make([]int, 64)
	if err := Each(context.Background(), s, work, func(context.Context, int) {
		n := running.Add(1)
		for {
			m := maxRunning.Load()
			if n <= m || maxRunning.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		running.Add(-1)
	}); err != nil {
		t.Fatalf("each: %v", err)
	}
	if got := maxRunning.Load(); got > limit {
		t.Fatalf("peak concurrency %d exceeded the limit %d", got, limit)
	}
	if s.Peak() > int64(limit) {
		t.Fatalf("reported peak %d exceeded the limit %d", s.Peak(), limit)
	}
}

// A cancelled context stops the run rather than draining every item.
func TestCancellationStopsTheRun(t *testing.T) {
	s := NewScheduler(2)
	ctx, cancel := context.WithCancel(context.Background())

	var done atomic.Int64
	work := make([]int, 500)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_ = Each(ctx, s, work, func(context.Context, int) {
		done.Add(1)
		time.Sleep(5 * time.Millisecond)
	})
	if done.Load() >= int64(len(work)) {
		t.Fatalf("all %d items ran despite cancellation", done.Load())
	}
}

// The derived default must be far above the core count: verification waits on the network,
// so sizing it like CPU work is what produced 28 sequential waves in the predecessor.
func TestDefaultConcurrencyIsSizedForWaiting(t *testing.T) {
	if got := DefaultConcurrency(); got < 128 || got > 1024 {
		t.Fatalf("default concurrency = %d, want between 128 and 1024", got)
	}
	if NewScheduler(0).Limit() != DefaultConcurrency() {
		t.Fatal("zero must mean the derived default")
	}
}
