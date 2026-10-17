package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// Resolver turns a hostname into exactly one vetted address to dial.
//
// The single-answer contract is the point. The predecessor resolved a name, vetted the
// result, and then handed the *name* to sing-box, which resolved it again — so a source
// controlling DNS could answer with a public address for the check and an internal one
// for the dial. Here the address that was vetted is the address that gets dialed, and
// nothing downstream is able to resolve anything (INV-33, INV-48, SEC-010).
type Resolver struct {
	// Lookup resolves a hostname. It is a field so a test can supply a fixture, and so
	// that a future implementation can pin to a specific DNS transport.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	// PreferIPv4 makes an A record win when both families are available. Runners
	// frequently have broken IPv6, and a node that is only reachable over v6 from the
	// verifier is not a node most users can reach either.
	PreferIPv4 bool
}

// NewResolver builds a resolver over the system DNS.
func NewResolver() *Resolver {
	return &Resolver{
		Lookup:     systemLookup,
		PreferIPv4: true,
	}
}

// Resolve returns one address that passed the egress guard.
//
// When a host has several addresses and some are denied, the denied ones are skipped
// rather than failing the host: a CDN-fronted node legitimately resolves to many
// addresses, and one bad answer should not lose the node. When *every* answer is denied,
// that is reported as a refusal, because it is the signature of a host that exists only
// to point inward.
func (r *Resolver) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	// A literal address needs no lookup, but it still needs vetting.
	if addr, err := netip.ParseAddr(host); err == nil {
		if verr := VetAddr(addr); verr != nil {
			return netip.Addr{}, verr
		}
		return addr.Unmap(), nil
	}

	lookup := r.Lookup
	if lookup == nil {
		lookup = systemLookup
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolving %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("resolving %q: no addresses", host)
	}

	ordered := make([]netip.Addr, len(addrs))
	copy(ordered, addrs)
	if r.PreferIPv4 {
		sort.SliceStable(ordered, func(i, j int) bool {
			return ordered[i].Unmap().Is4() && !ordered[j].Unmap().Is4()
		})
	}

	var lastDenial error
	for _, a := range ordered {
		a = a.Unmap()
		if verr := VetAddr(a); verr != nil {
			lastDenial = verr
			continue
		}
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("every address for %q was denied: %w", host, lastDenial)
}

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	var res net.Resolver
	return res.LookupNetIP(ctx, "ip", host)
}
