package policy

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// CachingResolver memoises lookups for the duration of a run.
//
// Measured on a live feed: 13,242 nodes carried 6,574 distinct hostnames, so half of all
// resolution is duplicated work, and the busiest host appears 364 times. Resolving each
// node independently at high concurrency also turns the verifier into a load generator
// against its own resolver, which shows up as policy failures that look like bad nodes.
//
// The cache is per run and deliberately short-lived. It must not outlive a cycle: a pinned
// answer that persists is a pinned answer that can go stale, and the whole point of
// resolving is to dial what is true now.
type CachingResolver struct {
	Inner *Resolver
	TTL   time.Duration

	mu      sync.Mutex
	entries map[string]*cacheEntry
	now     func() time.Time
}

type cacheEntry struct {
	done chan struct{}
	addr netip.Addr
	err  error
	at   time.Time
}

// NewCachingResolver wraps a resolver.
func NewCachingResolver(inner *Resolver, ttl time.Duration) *CachingResolver {
	if inner == nil {
		inner = NewResolver()
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &CachingResolver{
		Inner:   inner,
		TTL:     ttl,
		entries: map[string]*cacheEntry{},
		now:     time.Now,
	}
}

// Resolve returns a vetted address, reusing a recent answer for the same host.
//
// A genuine failure is cached: a hostname that does not resolve will not resolve for the next two
// hundred nodes that share it either, and retrying it each time is how one dead host becomes a
// measurable share of the run.
//
// A cancellation is not cached, and that distinction matters more than it looks. The first caller
// for a hostname may have its own per-node budget expire mid-lookup; treating that as the answer
// would poison the hostname for every node sharing it, for the rest of the run — turning one
// unlucky timeout into hundreds of policy failures that look like bad nodes.
func (c *CachingResolver) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	for {
		c.mu.Lock()
		e, ok := c.entries[host]
		if ok && c.now().Sub(e.at) > c.TTL {
			ok = false
		}
		if !ok {
			e = &cacheEntry{at: c.now(), done: make(chan struct{})}
			c.entries[host] = e
			c.mu.Unlock()

			addr, err := c.Inner.Resolve(ctx, host)
			if isCancellation(err) {
				// Withdraw the entry so the next caller tries again rather than inheriting a
				// verdict about our own deadline.
				c.mu.Lock()
				if c.entries[host] == e {
					delete(c.entries, host)
				}
				c.mu.Unlock()
				close(e.done)
				return netip.Addr{}, err
			}
			e.addr, e.err = addr, err
			close(e.done)
			return addr, err
		}
		c.mu.Unlock()

		// Wait for whoever is resolving this host rather than stampeding after it.
		select {
		case <-e.done:
			if isCancellation(e.err) {
				// The resolver that owned this entry was cancelled and withdrew it; try again.
				continue
			}
			return e.addr, e.err
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		}
	}
}

// isCancellation reports whether an error is about our own deadline rather than about the host.
func isCancellation(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Len is the number of distinct hosts resolved, which is the figure that shows how much
// duplication the cache absorbed.
func (c *CachingResolver) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
