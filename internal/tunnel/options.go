package tunnel

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/tuftytech/shellshift/internal/model"
)

// buildOptions translates a node into the typed options sing-box accepts.
//
// This replaces the predecessor layer whose defining property was that a malformed
// result took down fifty nodes at once. Two things changed. The result is a typed
// struct rather than a map assembled key by key, so a field that does not exist is a
// compile error instead of a runtime rejection. And the outbound is per node, so even a
// combination sing-box refuses costs exactly one node (INV-00).
func buildOptions(tgt Target, cfg Config) (any, error) {
	n := tgt.Node
	id := n.Identity
	if !tgt.Server.IsValid() {
		return nil, fmt.Errorf("tunnel: target has no resolved server address")
	}
	// The dialed address is the vetted one; the domain survives as the TLS server name
	// and the transport Host header. See Target for why this is mandatory (INV-48).
	server := option.ServerOptions{Server: tgt.Server.String(), ServerPort: id.Port}
	network := networkList(cfg)

	switch id.Protocol {
	case model.ProtoVLESS:
		opts := option.VLESSOutboundOptions{
			ServerOptions: server,
			UUID:          id.Credential,
			Flow:          n.Flow,
			Network:       network,
		}
		if n.PacketEncoding != "" {
			encoding := n.PacketEncoding
			opts.PacketEncoding = &encoding
		}
		opts.TLS = buildTLS(n, cfg)
		t, err := buildTransport(n)
		if err != nil {
			return nil, err
		}
		opts.Transport = t
		return opts, nil

	case model.ProtoVMess:
		opts := option.VMessOutboundOptions{
			ServerOptions: server,
			UUID:          id.Credential,
			// "auto" lets sing-box pick the cipher, which is what every modern client
			// does; the field is required and must not be left empty.
			Security: "auto",
			AlterId:  n.AlterID,
			Network:  network,
		}
		opts.TLS = buildTLS(n, cfg)
		t, err := buildTransport(n)
		if err != nil {
			return nil, err
		}
		opts.Transport = t
		return opts, nil

	case model.ProtoTrojan:
		opts := option.TrojanOutboundOptions{
			ServerOptions: server,
			Password:      id.Credential,
			Network:       network,
		}
		opts.TLS = buildTLS(n, cfg)
		t, err := buildTransport(n)
		if err != nil {
			return nil, err
		}
		opts.Transport = t
		return opts, nil

	case model.ProtoShadowsocks:
		// Shadowsocks accepts neither a v2ray transport nor a TLS block. Setting either
		// is a configuration rejection, so neither is set here (INV-08).
		opts := option.ShadowsocksOutboundOptions{
			ServerOptions: server,
			Method:        id.Method,
			Password:      id.Credential,
			Network:       network,
		}
		if id.Plugin != "" {
			opts.Plugin = id.Plugin
			opts.PluginOptions = formatPluginOptions(n.PluginOpts, n.PluginOptOrder)
		}
		return opts, nil

	case model.ProtoHysteria2:
		opts := option.Hysteria2OutboundOptions{
			ServerOptions: server,
			Password:      id.Credential,
			Network:       network,
		}
		// Port hopping: sing-box wants a list of low:high entries and treats the field
		// as conflicting with a single server port, so the single port is cleared.
		// Forgetting that clearing step is a configuration rejection (INV-09).
		if id.PortRange != "" {
			opts.ServerPorts = badoption.Listable[string](strings.Split(id.PortRange, ","))
			opts.ServerPort = 0
		}
		// TLS is unconditional for Hysteria2; only the verification stance is ours to
		// choose, and it is verification-on by default (INV-11, INV-30).
		opts.TLS = buildTLS(n, cfg)
		if opts.TLS != nil {
			opts.TLS.Enabled = true
		}
		// Only salamander exists, and only with a password. An unknown type makes
		// sing-box reject the configuration (INV-10).
		if n.Obfuscation == model.Hysteria2Obfuscation && n.ObfuscationPassword != "" {
			opts.Obfs = &option.Hysteria2Obfs{
				Type:     model.Hysteria2Obfuscation,
				Password: n.ObfuscationPassword,
			}
		}
		return opts, nil
	}

	return nil, fmt.Errorf("no option builder for protocol %q", id.Protocol)
}

func networkList(cfg Config) option.NetworkList {
	if cfg.UDPEnabled {
		return ""
	}
	return option.NetworkList(N.NetworkTCP)
}

// buildTLS assembles the TLS block, or returns nil when the node carries no TLS.
func buildTLS(n model.Node, cfg Config) *option.OutboundTLSOptions {
	id := n.Identity
	if id.Security == model.SecurityNone && id.Protocol != model.ProtoHysteria2 {
		return nil
	}

	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: id.SNI,
		// Certificate verification stays on. This single field is the difference between
		// proving a tunnel and proving that something answered (INV-30, INV-31).
		Insecure: cfg.AllowInsecureTLS,
	}
	if len(n.ALPN) > 0 {
		tls.ALPN = badoption.Listable[string](n.ALPN)
	}
	if n.Fingerprint != "" {
		tls.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: n.Fingerprint}
	}
	if id.Security == model.SecurityReality {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: id.PublicKey,
			// The key must be present even when empty (INV-16).
			ShortID: id.ShortID,
		}
	}
	return tls
}

// buildTransport assembles the v2ray transport block.
//
// The typing differences between transports are the classic source of configuration
// rejection: a Host that is a string for one transport and a list for another, a gRPC
// service name that must be present even when empty (INV-13).
func buildTransport(n model.Node) (*option.V2RayTransportOptions, error) {
	id := n.Identity
	switch id.Transport {
	case model.TransportTCP:
		return nil, nil

	case model.TransportWebSocket:
		path := id.Path
		if path == "" {
			path = "/"
		}
		t := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket}
		t.WebsocketOptions = option.V2RayWebsocketOptions{Path: path}
		// For websocket the authority goes in a header, not in a host field.
		if id.Host != "" {
			t.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": []string{id.Host}}
		}
		return t, nil

	case model.TransportGRPC:
		t := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC}
		// The key is always present; an empty service name is a value, not a gap.
		t.GRPCOptions = option.V2RayGRPCOptions{ServiceName: id.Path}
		return t, nil

	case model.TransportHTTPUpgrade:
		t := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade}
		// Host is a single string here.
		t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{Host: id.Host, Path: id.Path}
		return t, nil

	case model.TransportHTTP2:
		t := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP}
		// Host is a list here. Mixing this up with the httpupgrade case is exactly the
		// kind of mistake the type system now catches at compile time.
		http := option.V2RayHTTPOptions{Path: id.Path}
		if id.Host != "" {
			http.Host = badoption.Listable[string](splitAndTrim(id.Host))
		}
		t.HTTPOptions = http
		return t, nil

	case model.TransportQUIC:
		// Hysteria2 carries its own QUIC; a v2ray quic transport is not applicable.
		if id.Protocol == model.ProtoHysteria2 {
			return nil, nil
		}
		t := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}
		t.QUICOptions = option.V2RayQUICOptions{}
		return t, nil
	}
	return nil, fmt.Errorf("no transport builder for %q", id.Transport)
}

// formatPluginOptions renders SIP003 options back into the semicolon form sing-box
// expects. Keys are sorted so the rendering is deterministic, which matters because the
// result is compared in tests and hashed in fixtures.
func formatPluginOptions(opts map[string]string, order []string) string {
	if len(opts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(opts))
	seen := make(map[string]bool, len(opts))
	for _, k := range order {
		if _, ok := opts[k]; ok && !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(opts))
	for k := range opts {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sortStrings(rest)
	keys = append(keys, rest...)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if v := opts[k]; v != "" {
			parts = append(parts, k+"="+v)
		} else {
			parts = append(parts, k)
		}
	}
	return strings.Join(parts, ";")
}

func splitAndTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
