package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	M "github.com/sagernet/sing/common/metadata"
)

// InProcess dials through sing-box outbounds constructed inside this process.
//
// One outbound per node, built from typed options, with no configuration file, no
// listening socket and no child process. That is the whole point: the predecessor ran a
// sing-box process per batch of fifty nodes sharing one configuration, so a single
// rejected outbound prevented the process from binding and killed all fifty (INV-00).
// It also wrote that configuration, containing every credential in the batch, to a
// world-readable file next to the binary, and exposed an unauthenticated local proxy on
// a predictable port for the duration.
type InProcess struct {
	cfg Config

	mu     sync.Mutex
	ctx    context.Context
	logger log.ContextLogger
	closed bool
}

// NewInProcess builds a dialer. The context it prepares carries only an outbound
// registry: no inbound, no DNS transport and no service registry are needed, and asking
// for less means less of sing-box is reachable from a hostile node.
func NewInProcess(cfg Config) *InProcess {
	ctx := box.Context(context.Background(),
		nil, outbound.NewRegistry(), nil, nil, nil)
	return &InProcess{
		cfg:    cfg,
		ctx:    ctx,
		logger: log.NewNOPFactory().Logger(),
	}
}

// DialContext opens a connection to host:port through the node.
func (d *InProcess) DialContext(ctx context.Context, target Target, network, host string, port uint16) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, fmt.Errorf("tunnel: dialer is closed")
	}
	base := d.ctx
	logger := d.logger
	d.mu.Unlock()

	out, err := d.newOutbound(base, logger, target)
	if err != nil {
		return nil, fmt.Errorf("tunnel: building outbound: %w", err)
	}

	conn, err := out.DialContext(ctx, network, M.ParseSocksaddrHostPort(host, port))
	if err != nil {
		closeOutbound(out)
		return nil, err
	}
	// The outbound owns transport state, so its lifetime is tied to the connection
	// rather than to the dialer. A leaked outbound here is a leaked goroutine.
	return &ownedConn{Conn: conn, owner: out}, nil
}

// Close releases the dialer. Outbounds are owned by their connections, so there is
// nothing else to tear down.
func (d *InProcess) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// newOutbound constructs the protocol-specific outbound.
//
// The router argument is nil on purpose. None of these five constructors reads it, and
// passing nil means a hostile node cannot reach routing, DNS or any other subsystem
// through it.
func (d *InProcess) newOutbound(ctx context.Context, logger log.ContextLogger, target Target) (adapter.Outbound, error) {
	opts, err := buildOptions(target, d.cfg)
	if err != nil {
		return nil, err
	}
	tag := target.Node.Short()

	switch o := opts.(type) {
	case option.VLESSOutboundOptions:
		return vless.NewOutbound(ctx, nil, logger, tag, o)
	case option.VMessOutboundOptions:
		return vmess.NewOutbound(ctx, nil, logger, tag, o)
	case option.TrojanOutboundOptions:
		return trojan.NewOutbound(ctx, nil, logger, tag, o)
	case option.ShadowsocksOutboundOptions:
		return shadowsocks.NewOutbound(ctx, nil, logger, tag, o)
	case option.Hysteria2OutboundOptions:
		return hysteria2.NewOutbound(ctx, nil, logger, tag, o)
	}
	return nil, fmt.Errorf("tunnel: no constructor for %T", opts)
}

// ownedConn closes its outbound when the connection is closed.
type ownedConn struct {
	net.Conn
	owner any
	once  sync.Once
}

func (c *ownedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { closeOutbound(c.owner) })
	return err
}

func closeOutbound(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}
