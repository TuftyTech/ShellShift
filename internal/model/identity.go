package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Identity distinguishes one dialable endpoint from another.
//
// The rule is that every field which changes how a node is dialed belongs here, and
// nothing else does. The predecessor used
//
//	protocol:server:port:(uuid|password):transport
//
// which merged nodes that are genuinely different: two Reality endpoints on the same
// host, port and UUID but with different SNI or public key collapsed into one and the
// second was silently discarded; Shadowsocks nodes differing only in cipher collided;
// a Hysteria2 port range was represented by a single port (INV-21).
//
// Identity is compared through Key, never field by field, so adding a field
// automatically widens every comparison in the system.
type Identity struct {
	Protocol   Protocol
	Server     string // host or IP exactly as the source wrote it
	Port       uint16
	PortRange  string // canonical "20000:30000", empty when a single port
	Credential string // UUID or password or PSK
	Method     string // Shadowsocks cipher; empty otherwise
	Transport  Transport
	Security   Security
	SNI        string
	Host       string // transport Host header or authority
	Path       string
	PublicKey  string // Reality public key
	ShortID    string // Reality short id
	Plugin     string // canonical SIP003 plugin name
}

// canonical renders the identity as a stable, unambiguous string. Fields are
// length-prefixed so that no combination of values can be reinterpreted as a
// different combination: "ab" + "c" and "a" + "bc" must not collide.
func (id Identity) canonical() string {
	var b strings.Builder
	write := func(s string) {
		b.WriteString(itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte(';')
	}
	write(string(id.Protocol))
	write(strings.ToLower(id.Server))
	write(itoa(int(id.Port)))
	write(id.PortRange)
	write(id.Credential)
	write(strings.ToLower(id.Method))
	write(string(id.Transport))
	write(string(id.Security))
	write(strings.ToLower(id.SNI))
	write(strings.ToLower(id.Host))
	write(id.Path)
	write(id.PublicKey)
	write(id.ShortID)
	write(id.Plugin)
	return b.String()
}

// Key is the identity used for deduplication, pool membership and verdict lookup.
//
// It is a hash rather than the readable tuple for a reason that is not cosmetic: the
// tuple contains a credential, and the predecessor put that tuple into log lines,
// pool files and published labels. A hash discriminates exactly as well while being
// safe to write anywhere (GHOST-048).
func (id Identity) Key() string {
	sum := sha256.Sum256([]byte(id.canonical()))
	return hex.EncodeToString(sum[:])
}

// Short is the display form: the first eight hex characters of Key. Enough to tell
// two rows apart in a table, useless to an attacker.
func (id Identity) Short() string { return id.Key()[:8] }

// Endpoint is the network destination, for logging and grouping only. It is
// deliberately NOT an identity: the same host and port can serve many distinct nodes.
func (id Identity) Endpoint() string {
	return joinHostPort(id.Server, id.Port)
}

// itoa avoids importing strconv for two call sites and keeps canonical allocation-free
// for small integers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func joinHostPort(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + itoa(int(port))
	}
	return host + ":" + itoa(int(port))
}
