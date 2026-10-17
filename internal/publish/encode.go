package publish

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// safeSets record, per query key, which characters may stay unescaped.
//
// This is pure client-compatibility scar tissue, carried over deliberately. Real clients
// reject or mis-handle links where these are escaped differently, and the predecessor
// arrived at these sets by breaking real installations (INV-25).
var safeSets = map[string]string{
	"pbk": "", "sid": "", "flow": "", "fp": "", "type": "", "security": "",
	"encryption": "", "net": "", "tls": "", "protocol": "",
	"host": ".-_[]:", "sni": ".-_[]:", "peer": ".-_[]:",
	"alpn":        ",/",
	"serviceName": ".-_/",
	"obfs":        "", "obfs-password": "",
	"mport": ":,-",
	// The plugin string is a semicolon list the client re-parses, so its separators stay.
	"plugin": ";=,._-/",
	// Carried keys. spiderX is a path-shaped value, so it needs the same treatment as path:
	// fully escaped, which is what the default empty safe set gives.
	"spx": "", "authority": ".-_", "mux": "", "muxconcurrency": "",
	"fragment": ",-", "ech": "", "pqv": "", "fm": "", "prefix": "",
	"mode": "-_", "packetEncoding": "",
}

// alwaysEmit are keys whose empty value still carries meaning, so they survive
// serialisation rather than being dropped (INV-26).
var alwaysEmit = map[string]bool{"sid": true, "pbk": true, "path": true}

// Encode renders a node as a subscription URI.
//
// Two properties are load-bearing. The URI must re-decode to the same identity, which is
// what makes drift between the dialed configuration and the published one impossible —
// the predecessor kept these rules in three separate places and they had already
// diverged, publishing a VMess Reality node as ordinary TLS. And the URI must never carry
// a directive that disables certificate verification (INV-38).
func Encode(n model.Node, label string) (string, error) {
	switch n.Identity.Protocol {
	case model.ProtoVLESS:
		return encodeURLShape("vless", n, label), nil
	case model.ProtoTrojan:
		return encodeURLShape("trojan", n, label), nil
	case model.ProtoHysteria2:
		return encodeURLShape("hysteria2", n, label), nil
	case model.ProtoShadowsocks:
		return encodeShadowsocks(n, label), nil
	case model.ProtoVMess:
		return encodeVMess(n, label)
	}
	return "", fmt.Errorf("publish: no encoder for %q", n.Identity.Protocol)
}

func encodeURLShape(scheme string, n model.Node, label string) string {
	id := n.Identity
	params := map[string]string{}

	switch id.Protocol {
	case model.ProtoVLESS, model.ProtoTrojan:
		params["type"] = transportName(id.Transport)
		params["security"] = string(id.Security)
		if n.Flow != "" {
			params["flow"] = n.Flow
		}
		if n.Fingerprint != "" {
			params["fp"] = n.Fingerprint
		}
		if id.Security == model.SecurityReality {
			params["pbk"] = id.PublicKey
			params["sid"] = id.ShortID
		}
		if id.SNI != "" {
			params["sni"] = id.SNI
		}
		if id.Host != "" {
			params["host"] = id.Host
		}
		switch id.Transport {
		case model.TransportGRPC:
			params["serviceName"] = id.Path
		default:
			if id.Path != "" {
				params["path"] = id.Path
			}
		}
	case model.ProtoHysteria2:
		if id.SNI != "" {
			params["sni"] = id.SNI
		}
		if id.PortRange != "" {
			params["mport"] = strings.ReplaceAll(id.PortRange, ":", "-")
		}
		if n.Obfuscation != "" {
			params["obfs"] = n.Obfuscation
			params["obfs-password"] = n.ObfuscationPassword
		}
	}
	if len(n.ALPN) > 0 && !isDefaultALPN(n.ALPN) {
		params["alpn"] = strings.Join(n.ALPN, ",")
	}
	if n.PacketEncoding != "" {
		params["packetEncoding"] = n.PacketEncoding
	}
	// Carried parameters are written back last and never override a modelled one: what this
	// project decided about a node wins over what the source happened to say about it.
	for k, v := range n.Carried {
		if _, taken := params[k]; !taken {
			params[k] = v
		}
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(escape(id.Credential, ""))
	b.WriteByte('@')
	b.WriteString(hostForURI(id.Server))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(id.Port)))
	if q := renderQuery(params); q != "" {
		b.WriteByte('?')
		b.WriteString(q)
	}
	if label != "" {
		b.WriteByte('#')
		b.WriteString(escape(label, ""))
	}
	return b.String()
}

func encodeShadowsocks(n model.Node, label string) string {
	id := n.Identity
	cred := base64.RawStdEncoding.EncodeToString([]byte(id.Method + ":" + id.Credential))

	var b strings.Builder
	b.WriteString("ss://")
	b.WriteString(cred)
	b.WriteByte('@')
	b.WriteString(hostForURI(id.Server))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(id.Port)))

	params := map[string]string{}
	if id.Plugin != "" {
		plugin := id.Plugin
		if opts := renderPluginOpts(n.PluginOpts, n.PluginOptOrder); opts != "" {
			plugin += ";" + opts
		}
		params["plugin"] = plugin
	}
	for k, v := range n.Carried {
		if _, taken := params[k]; !taken {
			params[k] = v
		}
	}
	if q := renderQuery(params); q != "" {
		b.WriteByte('?')
		b.WriteString(q)
	}
	if label != "" {
		b.WriteByte('#')
		b.WriteString(escape(label, ""))
	}
	return b.String()
}

func encodeVMess(n model.Node, label string) (string, error) {
	id := n.Identity
	payload := map[string]any{
		"v":    "2",
		"add":  id.Server,
		"port": strconv.Itoa(int(id.Port)),
		"id":   id.Credential,
		"net":  transportName(id.Transport),
		"ps":   label,
	}
	if n.AlterID != 0 {
		payload["aid"] = strconv.Itoa(n.AlterID)
	}
	if id.Security == model.SecurityTLS {
		payload["tls"] = "tls"
	} else {
		payload["tls"] = ""
	}
	if id.Host != "" {
		payload["host"] = id.Host
	}
	if id.Path != "" {
		payload["path"] = id.Path
	}
	if id.SNI != "" {
		payload["sni"] = id.SNI
	}
	if n.Fingerprint != "" {
		payload["fp"] = n.Fingerprint
	}
	if len(n.ALPN) > 0 && !isDefaultALPN(n.ALPN) {
		payload["alpn"] = strings.Join(n.ALPN, ",")
	}
	for k, v := range n.Carried {
		if _, taken := payload[k]; !taken {
			payload[k] = v
		}
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	// Unpadded base64 is what clients expect in a VMess payload (INV-27).
	return "vmess://" + base64.RawStdEncoding.EncodeToString(raw), nil
}

// renderQuery writes parameters in a stable order with per-key escaping.
//
// Order is alphabetical rather than insertion-dependent because published output must be
// byte-stable under regeneration from unchanged inputs (PERF-041). The predecessor had a
// placeholder-ordering hazard of the same family: two template tokens where one only
// survived because it was substituted before the other.
func renderQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v == "" && !alwaysEmit[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+escape(params[k], safeSets[k]))
	}
	return strings.Join(parts, "&")
}

func renderPluginOpts(opts map[string]string, order []string) string {
	if len(opts) == 0 {
		return ""
	}
	keys := pluginKeyOrder(opts, order)

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

// escape percent-encodes a value, leaving the characters in safe unescaped.
//
// It is written by hand rather than delegated to url.QueryEscape because that function
// encodes a space as a plus sign, which several proxy clients read literally, and because
// the per-key safe sets have no equivalent in the standard library.
func escape(s, safe string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			const hex = "0123456789ABCDEF"
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// hostForURI brackets an IPv6 literal, which is required for the authority to parse.
func hostForURI(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

// transportName maps back to the wire name a client expects. The canonical internal name
// and the published name are not always the same word.
func transportName(t model.Transport) string {
	switch t {
	case model.TransportTCP:
		return "tcp"
	case model.TransportWebSocket:
		return "ws"
	case model.TransportGRPC:
		return "grpc"
	case model.TransportHTTPUpgrade:
		return "httpupgrade"
	case model.TransportHTTP2:
		return "http"
	case model.TransportQUIC:
		return "quic"
	}
	return string(t)
}

// isDefaultALPN reports whether the list is the default the decoder supplies, so that a
// value nobody chose is not written back out as though it had been.
func isDefaultALPN(alpn []string) bool {
	return len(alpn) == 2 && alpn[0] == "h2" && alpn[1] == "http/1.1"
}

// pluginKeyOrder returns the option keys in the producer order, falling back to sorted order
// for anything the order does not mention. Both are deterministic; the first is also faithful.
func pluginKeyOrder(opts map[string]string, order []string) []string {
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
	sort.Strings(rest)
	return append(keys, rest...)
}
