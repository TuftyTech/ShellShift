package policy

import (
	"context"
	"net/netip"
	"testing"

	"github.com/tuftytech/shellshift/internal/model"
)

// One case per denied range. The predecessor blocked three of these and skipped the
// check entirely for UDP protocols, which is how an attacker-supplied hostname could
// reach the cloud metadata service from a CI runner (INV-33).
func TestDeniedRanges(t *testing.T) {
	denied := []struct{ addr, why string }{
		{"0.0.0.0", "this network"},
		{"0.1.2.3", "this network"},
		{"10.0.0.1", "private"},
		{"10.255.255.255", "private"},
		{"100.64.0.1", "carrier-grade NAT"},
		{"100.127.255.255", "carrier-grade NAT"},
		{"127.0.0.1", "loopback"},
		{"127.255.255.254", "loopback"},
		{"169.254.169.254", "cloud metadata"},
		{"169.254.0.1", "link-local"},
		{"172.16.0.1", "private"},
		{"172.31.255.255", "private"},
		{"192.0.0.1", "protocol assignments"},
		{"192.0.2.1", "documentation"},
		{"192.168.1.1", "private"},
		{"198.18.0.1", "benchmarking"},
		{"198.51.100.1", "documentation"},
		{"203.0.113.1", "documentation"},
		{"224.0.0.1", "multicast"},
		{"239.255.255.255", "multicast"},
		{"255.255.255.255", "reserved"},
		{"::", "unspecified"},
		{"::1", "loopback"},
		{"64:ff9b::1", "NAT64"},
		{"100::1", "discard-only"},
		{"2001:db8::1", "documentation"},
		{"fc00::1", "unique local"},
		{"fd12:3456::1", "unique local"},
		{"fe80::1", "link-local"},
		{"ff02::1", "multicast"},
	}

	for _, tc := range denied {
		t.Run(tc.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)
			if err := VetAddr(addr); err == nil {
				t.Fatalf("%s (%s) was allowed", tc.addr, tc.why)
			}
		})
	}
}

// An IPv4-mapped IPv6 address must be judged by its IPv4 rules. Without unmapping, every
// prefix rule above can be walked straight past by writing the same address differently.
func TestIPv4MappedAddressesCannotBypassTheRules(t *testing.T) {
	bypass := []string{
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:169.254.169.254",
		"::ffff:192.168.1.1",
		"::ffff:100.64.0.1",
	}
	for _, s := range bypass {
		t.Run(s, func(t *testing.T) {
			if err := VetAddr(netip.MustParseAddr(s)); err == nil {
				t.Fatalf("%s bypassed the guard", s)
			}
		})
	}
}

func TestPublicAddressesAreAllowed(t *testing.T) {
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34", "172.15.255.255", "172.32.0.1",
		"100.63.255.255", "100.128.0.1", "2606:4700:4700::1111", "2a00:1450:4001::1",
	}
	for _, s := range allowed {
		t.Run(s, func(t *testing.T) {
			if err := VetAddr(netip.MustParseAddr(s)); err != nil {
				t.Fatalf("%s was denied: %v", s, err)
			}
		})
	}
}

func TestInvalidAddressIsDenied(t *testing.T) {
	if err := VetAddr(netip.Addr{}); err == nil {
		t.Fatal("the zero address must be denied")
	}
}

// INV-34. CDN and public-resolver ranges are refused, but only for transports a CDN could not
// be carrying. A CDN terminates HTTP, so a websocket or gRPC node in a Cloudflare range is
// ordinary; a bare TCP or QUIC node at 1.1.1.1 is not a proxy endpoint at all.
//
// These ranges are global unicast, so VetAddr passes them by design — the judgement needs to
// know the transport, which is why it lives in VetNodeAddr.
func TestFrontedRangesRequireAFrontableTransport(t *testing.T) {
	// One case per range in the list, so a removed entry fails rather than going unnoticed.
	fronted := []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
		"162.159.192.1", "104.16.0.1", "172.64.0.1",
	}

	t.Run("refused for a transport a CDN cannot carry", func(t *testing.T) {
		for _, transport := range []model.Transport{model.TransportTCP, model.TransportQUIC} {
			for _, s := range fronted {
				addr := netip.MustParseAddr(s)
				node := model.Node{Identity: model.Identity{Transport: transport}}
				if err := VetNodeAddr(node, addr); err == nil {
					t.Fatalf("%s over %s was allowed", s, transport)
				}
				// The plain address check must still pass it: this is a judgement about the
				// pairing, not about the address.
				if err := VetAddr(addr); err != nil {
					t.Fatalf("VetAddr(%s) = %v, want nil: the range is global unicast", s, err)
				}
			}
		}
	})

	t.Run("allowed for a transport a CDN legitimately fronts", func(t *testing.T) {
		for _, transport := range []model.Transport{
			model.TransportWebSocket, model.TransportGRPC, model.TransportHTTPUpgrade,
		} {
			for _, s := range fronted {
				node := model.Node{Identity: model.Identity{Transport: transport}}
				if err := VetNodeAddr(node, netip.MustParseAddr(s)); err != nil {
					t.Fatalf("%s over %s was denied: %v", s, transport, err)
				}
			}
		}
	})

	t.Run("an ordinary address is unaffected", func(t *testing.T) {
		node := model.Node{Identity: model.Identity{Transport: model.TransportTCP}}
		if err := VetNodeAddr(node, netip.MustParseAddr("93.184.216.34")); err != nil {
			t.Fatalf("an ordinary address was denied: %v", err)
		}
	})

	t.Run("the address rules still apply", func(t *testing.T) {
		// A CDN-capable transport does not buy an exemption from VetAddr. The predecessor
		// skipped the whole guard for a class of nodes, which is INV-33.
		node := model.Node{Identity: model.Identity{Transport: model.TransportWebSocket}}
		for _, s := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.5"} {
			if err := VetNodeAddr(node, netip.MustParseAddr(s)); err == nil {
				t.Fatalf("%s was allowed for a CDN-capable transport", s)
			}
		}
	})
}

// A hostname that resolves to a mixture keeps its usable answer: a CDN-fronted node
// legitimately has many addresses, and one bad answer must not lose the node.
func TestResolverSkipsDeniedAnswers(t *testing.T) {
	r := &Resolver{
		Lookup: fixedLookup(
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("10.0.0.5"),
			netip.MustParseAddr("93.184.216.34"),
		),
	}
	got, err := r.Resolve(context.Background(), "mixed.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.String() != "93.184.216.34" {
		t.Fatalf("resolved to %s, want the public answer", got)
	}
}

// A hostname whose every answer is internal is the signature of a host that exists only
// to point inward, and it is refused rather than silently skipped.
func TestResolverRefusesWhenEveryAnswerIsDenied(t *testing.T) {
	r := &Resolver{
		Lookup: fixedLookup(
			netip.MustParseAddr("169.254.169.254"),
			netip.MustParseAddr("192.168.0.1"),
		),
	}
	if _, err := r.Resolve(context.Background(), "inward.example.com"); err == nil {
		t.Fatal("a host resolving only to denied addresses must be refused")
	}
}

// This is the rebinding case stated as a test: whatever the resolver returns is what gets
// dialed, so a second answer cannot be substituted later.
func TestResolveReturnsOneVettedAddress(t *testing.T) {
	first := netip.MustParseAddr("93.184.216.34")
	r := &Resolver{Lookup: fixedLookup(first)}
	got, err := r.Resolve(context.Background(), "pinned.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != first {
		t.Fatalf("resolved to %s, want %s", got, first)
	}
	if err := VetAddr(got); err != nil {
		t.Fatalf("the returned address must already be vetted: %v", err)
	}
}

func TestLiteralAddressIsStillVetted(t *testing.T) {
	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("a loopback literal must be refused without any lookup")
	}
	got, err := r.Resolve(context.Background(), "93.184.216.34")
	if err != nil {
		t.Fatalf("a public literal must be accepted: %v", err)
	}
	if got.String() != "93.184.216.34" {
		t.Fatalf("got %s", got)
	}
}

func TestPreferIPv4(t *testing.T) {
	v6 := netip.MustParseAddr("2606:4700:4700::1111")
	v4 := netip.MustParseAddr("1.1.1.1")
	r := &Resolver{Lookup: fixedLookup(v6, v4), PreferIPv4: true}
	got, err := r.Resolve(context.Background(), "dual.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != v4 {
		t.Fatalf("got %s, want the IPv4 answer", got)
	}
}

func fixedLookup(addrs ...netip.Addr) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) { return addrs, nil }
}
