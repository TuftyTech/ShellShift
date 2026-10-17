package policy

import (
	"fmt"
	"net/netip"

	"github.com/tuftytech/shellshift/internal/model"
)

// deniedPrefixes are ranges an outbound target may never resolve to.
//
// The predecessor blocked only loopback, private and unspecified addresses, and skipped
// the check entirely for UDP protocols. It did not block the cloud metadata range, which
// on a CI runner is the single most valuable thing an attacker-supplied hostname could
// point at. This list is exhaustive by intent and applies to every protocol and every
// transport with no exemptions (INV-33, SEC-009).
var deniedPrefixes = []struct {
	prefix netip.Prefix
	why    string
}{
	// IPv4.
	{netip.MustParsePrefix("0.0.0.0/8"), "this network"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local, includes cloud metadata"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
	// IPv6.
	{netip.MustParsePrefix("::/128"), "unspecified"},
	{netip.MustParsePrefix("::1/128"), "loopback"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "IPv4-mapped, would bypass the IPv4 rules"},
	{netip.MustParsePrefix("64:ff9b::/96"), "NAT64"},
	{netip.MustParsePrefix("100::/64"), "discard-only"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	{netip.MustParsePrefix("fc00::/7"), "unique local"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
}

// frontedPrefixes are ranges that belong to public resolvers and CDNs.
//
// These are global unicast and perfectly reachable, so VetAddr passes them. What makes them
// suspicious is what they cannot be: a node whose address is a public DNS resolver is not a
// proxy endpoint, and a bare TCP or QUIC node sitting inside a CDN range is not something a
// CDN can carry — the CDN terminates HTTP, so only an HTTP-shaped transport can be fronted
// by one. A websocket or gRPC node in the same range is ordinary and expected.
//
// The list is the predecessor's, which measured it against a real catalogue
// (_legacy/angra_core.go:102-105,353-363), plus a note about why each entry is here (INV-34,
// GHOST-019).
var frontedPrefixes = []struct {
	prefix netip.Prefix
	why    string
}{
	{netip.MustParsePrefix("1.1.1.0/24"), "Cloudflare public resolver"},
	{netip.MustParsePrefix("1.0.0.0/24"), "Cloudflare public resolver"},
	{netip.MustParsePrefix("8.8.8.0/24"), "Google public resolver"},
	{netip.MustParsePrefix("8.8.4.0/24"), "Google public resolver"},
	{netip.MustParsePrefix("162.159.0.0/16"), "Cloudflare"},
	{netip.MustParsePrefix("104.16.0.0/12"), "Cloudflare"},
	{netip.MustParsePrefix("172.64.0.0/13"), "Cloudflare"},
}

// EgressError is a refusal to dial an address.
type EgressError struct {
	Addr netip.Addr
	Why  string
}

func (e *EgressError) Error() string {
	return fmt.Sprintf("egress denied for %s: %s", e.Addr, e.Why)
}

// VetAddr reports whether an address may be dialed.
//
// The check is an allowlist in spirit even though it is written as a deny list: anything
// that is not a global unicast address is refused first, and then the specific ranges
// that are technically global unicast but must never be reached are refused too.
func VetAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return &EgressError{Addr: addr, Why: "not a valid address"}
	}
	// Unmap first. An IPv4-mapped IPv6 address must be judged by its IPv4 rules, which
	// is the trick that would otherwise walk straight past every prefix above.
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback():
		return &EgressError{Addr: addr, Why: "loopback"}
	case addr.IsUnspecified():
		return &EgressError{Addr: addr, Why: "unspecified"}
	case addr.IsPrivate():
		return &EgressError{Addr: addr, Why: "private"}
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return &EgressError{Addr: addr, Why: "link-local"}
	case addr.IsInterfaceLocalMulticast(), addr.IsMulticast():
		return &EgressError{Addr: addr, Why: "multicast"}
	}

	for _, d := range deniedPrefixes {
		if d.prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if d.prefix.Contains(addr) {
			return &EgressError{Addr: addr, Why: d.why}
		}
	}

	if !addr.IsGlobalUnicast() {
		return &EgressError{Addr: addr, Why: "not global unicast"}
	}
	return nil
}

// VetNodeAddr is VetAddr plus the checks that need to know what the node is.
//
// It exists separately because the two questions are different. VetAddr asks whether an
// address may ever be dialed, and that answer cannot depend on the node — making it
// node-dependent is how the predecessor ended up skipping the whole guard for UDP protocols
// (INV-33). This asks the narrower question of whether *this* node resolving to *this*
// address makes sense, which does depend on the transport (INV-34).
func VetNodeAddr(node model.Node, addr netip.Addr) error {
	if err := VetAddr(addr); err != nil {
		return err
	}
	if node.Identity.Transport.CDNCapable() {
		return nil
	}
	unmapped := addr.Unmap()
	for _, f := range frontedPrefixes {
		if f.prefix.Addr().Is4() != unmapped.Is4() {
			continue
		}
		if f.prefix.Contains(unmapped) {
			return &EgressError{
				Addr: unmapped,
				Why: fmt.Sprintf("%s cannot front a %s transport", f.why,
					node.Identity.Transport),
			}
		}
	}
	return nil
}
