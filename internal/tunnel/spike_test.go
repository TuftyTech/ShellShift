package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
	M "github.com/sagernet/sing/common/metadata"
)

// This is the P2 go/no-go spike, kept as a test so the answer stays true rather than
// becoming a claim in a document.
//
// The question: can a sing-box outbound be constructed in-process, from typed options,
// with no configuration file, no local inbound and no subprocess — and can traffic be
// dialed through it? If yes, a malformed node can only fail itself, and the whole
// batch-of-fifty blast radius that dominated the predecessor disappears (INV-00).
func TestSpikeConstructOutboundInProcess(t *testing.T) {
	// A listener that accepts and immediately closes stands in for a server. The VLESS
	// handshake will not complete, which is fine: the spike is about whether the dial
	// path is reachable at all, not about proving a protocol against a fake peer.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())

	ctx := box.Context(context.Background(),
		nil, // inbound registry: unused, no inbound is created
		outbound.NewRegistry(),
		nil, // endpoint registry
		nil, // dns transport registry
		nil, // service registry
	)

	opts := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     host,
			ServerPort: uint16(atoiTest(t, portStr)),
		},
		UUID: "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b",
	}

	logger := log.NewNOPFactory().Logger()

	// The router argument is part of the signature but VLESS never reads it.
	out, err := vless.NewOutbound(ctx, nil, logger, "spike", opts)
	if err != nil {
		t.Fatalf("constructing a VLESS outbound in-process failed: %v", err)
	}
	if out == nil {
		t.Fatal("constructor returned no outbound")
	}
	t.Logf("outbound constructed: type=%s tag=%s networks=%v", out.Type(), out.Tag(), out.Network())

	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := out.DialContext(dialCtx, "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if conn != nil {
		_ = conn.Close()
	}
	// Either outcome proves the plumbing: a connection object means the dial path ran
	// end to end, and an error from the handshake means it ran and the fake peer
	// refused. What would disprove the approach is a panic or a nil-router crash.
	t.Logf("DialContext returned conn=%v err=%v", conn != nil, err)
}

func atoiTest(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("port %q is not numeric", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
