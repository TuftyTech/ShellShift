package model

import "fmt"

// Protocol is a proxy protocol ShellShift understands. The set is closed: an
// unrecognised scheme is rejected at the boundary rather than carried forward as a
// string and discovered later (GHOST-049).
type Protocol string

const (
	ProtoVLESS       Protocol = "vless"
	ProtoVMess       Protocol = "vmess"
	ProtoTrojan      Protocol = "trojan"
	ProtoShadowsocks Protocol = "shadowsocks"
	ProtoHysteria2   Protocol = "hysteria2"
)

var protocolsByScheme = map[string]Protocol{
	"vless":     ProtoVLESS,
	"vmess":     ProtoVMess,
	"trojan":    ProtoTrojan,
	"ss":        ProtoShadowsocks,
	"hy2":       ProtoHysteria2,
	"hysteria2": ProtoHysteria2,
}

// ProtocolForScheme maps a URI scheme to a protocol.
//
// Note what is absent: "hysteria" (v1). The predecessor accepted it in one code path
// and ignored it in another, so v1 links were dropped from sources but admitted from
// the pool and treated as v2 (INV-12, GHOST-053). Until v1 is genuinely supported the
// scheme is rejected everywhere, consistently.
func ProtocolForScheme(scheme string) (Protocol, bool) {
	p, ok := protocolsByScheme[scheme]
	return p, ok
}

// UsesUDP reports whether the protocol carries its transport over UDP/QUIC. Such
// nodes skip a TCP reachability probe, but they never skip address vetting: the
// predecessor returned early from the whole check for these, leaving the egress guard
// unenforced (INV-33, GHOST-017).
func (p Protocol) UsesUDP() bool { return p == ProtoHysteria2 }

// Transport is the stream transport carried inside the protocol.
type Transport string

const (
	TransportTCP         Transport = "tcp"
	TransportWebSocket   Transport = "ws"
	TransportGRPC        Transport = "grpc"
	TransportHTTPUpgrade Transport = "httpupgrade"
	TransportHTTP2       Transport = "http"
	TransportQUIC        Transport = "quic"
)

var transportAliases = map[string]Transport{
	"":            TransportTCP,
	"tcp":         TransportTCP,
	"raw":         TransportTCP,
	"none":        TransportTCP,
	"ws":          TransportWebSocket,
	"websocket":   TransportWebSocket,
	"grpc":        TransportGRPC,
	"httpupgrade": TransportHTTPUpgrade,
	"xhttp":       TransportHTTPUpgrade,
	"http":        TransportHTTP2,
	"h2":          TransportHTTP2,
	"quic":        TransportQUIC,
}

// ParseTransport canonicalises a transport name. Unknown values collapse to TCP,
// which is the predecessor behaviour: an unrecognised transport degrades to no
// transport block rather than failing the node (GHOST-050).
func ParseTransport(s string) Transport {
	if t, ok := transportAliases[s]; ok {
		return t
	}
	return TransportTCP
}

// CDNCapable reports whether the transport is legitimately fronted by a CDN, which is
// what makes a node resolving into a CDN range acceptable instead of suspicious
// (INV-34, GHOST-019).
func (t Transport) CDNCapable() bool {
	switch t {
	case TransportWebSocket, TransportGRPC, TransportHTTPUpgrade:
		return true
	}
	return false
}

// Security is the TLS layer wrapping the transport.
type Security string

const (
	SecurityNone    Security = "none"
	SecurityTLS     Security = "tls"
	SecurityReality Security = "reality"
)

var securityAliases = map[string]Security{
	"":        SecurityNone,
	"none":    SecurityNone,
	"tls":     SecurityTLS,
	"reality": SecurityReality,
	// The predecessor accepted "auto" and treated it as TLS.
	"auto": SecurityTLS,
	// Some producers write a boolean where a mode name belongs. A live feed carried 181
	// nodes with security=false, which unambiguously means no TLS; rejecting them as an
	// unknown mode threw away readable input over a formatting choice.
	"false": SecurityNone,
	"0":     SecurityNone,
	"true":  SecurityTLS,
	"1":     SecurityTLS,
}

// ParseSecurity canonicalises a security mode. Unlike Transport, an unrecognised
// value is an error: silently downgrading a node to plaintext would publish something
// weaker than the source advertised.
func ParseSecurity(s string) (Security, error) {
	if sec, ok := securityAliases[s]; ok {
		return sec, nil
	}
	return "", fmt.Errorf("unknown security mode %q", s)
}

// Fingerprints is the closed set of uTLS fingerprints sing-box accepts. A value
// outside it made the predecessor force "chrome"; ShellShift keeps that behaviour but
// the allowlist lives in exactly one place (INV-17, GHOST-051).
var Fingerprints = map[string]bool{
	"chrome": true, "firefox": true, "edge": true, "safari": true,
	"360": true, "qq": true, "ios": true, "android": true,
	"random": true, "randomized": true,
}

// DefaultFingerprint is substituted when a node names an unsupported one.
const DefaultFingerprint = "chrome"

// ShadowsocksMethods is the closed set of accepted ciphers. A node outside it is
// rejected rather than attempted (INV-05, GHOST-006).
var ShadowsocksMethods = map[string]bool{
	"aes-128-gcm":                   true,
	"aes-192-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-ietf-poly1305":        true,
	"xchacha20-ietf-poly1305":       true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
}

// KeyLenForMethod returns the exact PSK byte length a 2022-blake3 cipher requires,
// and false for ciphers that carry no such requirement. A wrong length is a fatal
// sing-box start, which is why it is checked before the node is ever dialed
// (INV-06, GHOST-009).
func KeyLenForMethod(method string) (int, bool) {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16, true
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32, true
	}
	return 0, false
}

// Hysteria2Obfuscation is the only obfuscation type sing-box accepts. Anything else
// makes it reject the configuration (INV-10, GHOST-052).
const Hysteria2Obfuscation = "salamander"

// SIP003Plugins maps accepted plugin names to their canonical sing-box name.
// Anything absent from this map causes the node to be dropped (INV-07).
var SIP003Plugins = map[string]string{
	"obfs-local":   "obfs-local",
	"simple-obfs":  "obfs-local",
	"v2ray-plugin": "v2ray-plugin",
}
