package tunnel

import (
	"context"
	"net"
	"net/netip"

	"github.com/tuftytech/shellshift/internal/model"
)

// Target is a node together with the address its server name resolved to.
//
// The resolved address is required, not optional, and that is a design decision with two
// independent justifications that happen to coincide.
//
// Security: the egress guard must resolve once, vet the result, and dial exactly that
// address. The predecessor resolved, vetted, and then let sing-box resolve the name a
// second time, leaving a window in which a hostile source could answer with a public
// address for the check and an internal one for the dial (INV-33).
//
// Mechanics: an in-process sing-box outbound handed a domain name asks the context for a
// DNS transport, and providing one means instantiating sing-box DNS, routing and service
// registries — a large amount of machinery reachable from hostile input. Handing it a
// literal address removes that requirement entirely (INV-48).
//
// The domain never disappears: it remains the TLS server name and the transport Host
// header, which is what the far end actually checks.
type Target struct {
	Node model.Node
	// Server is the vetted address to dial. It must be valid.
	Server netip.Addr
}

// Dialer opens connections through a proxy node.
//
// Every use of sing-box is confined behind this interface. That containment is
// deliberate: the library exposes no compatibility guarantee across minor versions, so
// an upgrade must be able to break exactly one implementation rather than the whole
// verification path. It also makes a second implementation possible, and a second
// implementation is what turns "we believe these agree" into a test.
type Dialer interface {
	// DialContext opens a connection to host:port through the target. The returned
	// connection is the caller's to close.
	DialContext(ctx context.Context, target Target, network, host string, port uint16) (net.Conn, error)

	// Close releases whatever the dialer holds. Calling it twice is safe.
	Close() error
}

// Config tunes a dialer.
type Config struct {
	// AllowInsecureTLS disables certificate verification.
	//
	// It defaults to false and there is no path that turns it on implicitly. The
	// predecessor set the equivalent flag unconditionally for every TLS node and then
	// published that setting to users, so a quarter of the catalogue shipped with
	// verification disabled (INV-30). Any use of this must be a visible, deliberate
	// decision recorded next to the nodes it applies to.
	AllowInsecureTLS bool

	// UDPEnabled advertises UDP support on the outbound. Verification only needs TCP,
	// and asking for less reduces what a hostile node can attempt.
	UDPEnabled bool
}
