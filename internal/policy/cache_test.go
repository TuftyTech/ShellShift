package policy

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Half of all resolution on a live feed is duplicated: 13,242 nodes carried 6,574 distinct
// hostnames, and the busiest host appeared 364 times.
func TestCacheAnswersRepeatsWithoutLookingUpAgain(t *testing.T) {
	var calls atomic.Int64
	inner := &Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}
	c := NewCachingResolver(inner, time.Minute)

	for i := 0; i < 50; i++ {
		if _, err := c.Resolve(context.Background(), "busy.example.com"); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("made %d lookups for one host, want 1", calls.Load())
	}
}

// A genuine failure is cached: a host that does not resolve will not resolve for the next two
// hundred nodes sharing it either.
func TestGenuineFailuresAreCached(t *testing.T) {
	var calls atomic.Int64
	inner := &Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, errors.New("no such host")
	}}
	c := NewCachingResolver(inner, time.Minute)

	for i := 0; i < 10; i++ {
		if _, err := c.Resolve(context.Background(), "gone.example.com"); err == nil {
			t.Fatal("expected a failure")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("made %d lookups, want 1: a genuine failure must be cached", calls.Load())
	}
}

// INV-54. A cancellation is not an answer about a hostname. The first caller for a host may have its own
// per-node budget expire mid-lookup, and caching that would poison the host for every node
// sharing it for the rest of the run — one unlucky timeout becoming hundreds of policy failures
// that look like bad nodes.
func TestCancellationIsNotCachedAsAnAnswer(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	inner := &Resolver{Lookup: func(ctx context.Context, _ string) ([]netip.Addr, error) {
		n := calls.Add(1)
		if n == 1 {
			// The first caller waits and is cancelled.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
			}
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}
	c := NewCachingResolver(inner, time.Minute)

	first, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := c.Resolve(first, "shared.example.com"); err == nil {
			t.Error("the cancelled caller should have failed")
		}
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	wg.Wait()
	close(release)

	// A later node sharing the host must get a real answer, not the earlier cancellation.
	addr, err := c.Resolve(context.Background(), "shared.example.com")
	if err != nil {
		t.Fatalf("a later caller inherited the cancellation: %v", err)
	}
	if addr.String() != "93.184.216.34" {
		t.Fatalf("resolved to %s", addr)
	}
}

// Concurrent callers for the same host wait for one lookup rather than stampeding after it.
func TestConcurrentCallersShareOneLookup(t *testing.T) {
	var calls atomic.Int64
	inner := &Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}
	c := NewCachingResolver(inner, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Resolve(context.Background(), "hot.example.com"); err != nil {
				t.Errorf("resolve: %v", err)
			}
		}()
	}
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("made %d lookups for 32 concurrent callers, want 1", calls.Load())
	}
}

// The cache must not outlive its usefulness: a pinned answer that persists is a pinned answer
// that can go stale, and the point of resolving is to dial where the node is now.
func TestEntriesExpire(t *testing.T) {
	var calls atomic.Int64
	inner := &Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}
	now := time.Now()
	c := NewCachingResolver(inner, time.Minute)
	c.now = func() time.Time { return now }

	if _, err := c.Resolve(context.Background(), "a.example.com"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.Resolve(context.Background(), "a.example.com"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("made %d lookups, want 2: the entry should have expired", calls.Load())
	}
}
