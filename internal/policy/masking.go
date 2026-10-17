package policy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// AddressResolver is the resolving contract this package needs, stated as an interface so a
// caller can supply the per-run caching resolver rather than a fresh lookup per node.
type AddressResolver interface {
	Resolve(ctx context.Context, host string) (netip.Addr, error)
}

// MaskingProver checks that a Reality server name names a real site.
//
// This is the addition that turns the whitelist class from a list lookup into a measurement.
// The predecessor asked only whether the server name appeared in a whitelist feed, which a
// node can satisfy by naming any popular domain it likes. What actually has to be true for
// Reality masking to work is that the named site really is there and really serves a valid
// certificate for that name — otherwise the disguise does not survive inspection.
//
// The recovered audit of the predecessor asked for exactly this check and it was never built
// (audit-2026-06.md, section 5.1).
type MaskingProver struct {
	Resolver AddressResolver
	Timeout  time.Duration

	mu      sync.Mutex
	results map[string]maskResult
	now     func() time.Time
	// TTL bounds how long a verdict is reused. Masking is a property of the covered site,
	// not of the node, so it changes slowly — but not never.
	TTL time.Duration

	// dial and tlsConfig are injectable so the proof itself can be tested against a local
	// server. Production leaves them nil, which means the real dialer and the system roots.
	dial      func(ctx context.Context, addr netip.Addr) (net.Conn, error)
	tlsConfig func(serverName string) *tls.Config
}

type maskResult struct {
	ok    bool
	err   error
	at    time.Time
	cover CoverCert
}

// CoverCert is what the proof saw on the covered site.
//
// The handshake that proves masking already has all of it, and the prover used to keep a boolean
// and throw the rest away. That made the strongest claim on the page the least legible one: "the
// disguise checked out" and "the disguise is a Let's Encrypt certificate issued to
// www.microsoft.com, valid until March, over TLS 1.3" are different amounts of evidence, and only
// the second lets a reader judge it. Fields are empty when the handshake never got that far —
// there is no such thing here as a certificate that was not seen.
type CoverCert struct {
	// Issuer and Subject are common names, which is what a reader recognises. The full
	// distinguished name is noise on a card.
	Issuer  string
	Subject string
	// NotBefore and NotAfter are the validity window, in UTC.
	NotBefore time.Time
	NotAfter  time.Time
	// TLSVersion is the negotiated version, as words rather than a number.
	TLSVersion string
	// Proven repeats the verdict, so a caller holding only this value can still tell a refusal
	// from a success without a second lookup.
	Proven bool
}

// NewMaskingProver builds a prover over a resolver.
func NewMaskingProver(resolver AddressResolver) *MaskingProver {
	return &MaskingProver{
		Resolver: resolver,
		Timeout:  4 * time.Second,
		results:  map[string]maskResult{},
		now:      time.Now,
		TTL:      30 * time.Minute,
	}
}

// Prove reports whether the server name serves a valid certificate for itself.
//
// The connection is direct, not through the node: the question is about the covered site, and
// asking the node about its own cover would let it answer for itself.
func (m *MaskingProver) Prove(ctx context.Context, serverName string) (bool, error) {
	if serverName == "" {
		return false, fmt.Errorf("masking: no server name")
	}

	m.mu.Lock()
	if r, ok := m.results[serverName]; ok && m.now().Sub(r.at) < m.TTL {
		m.mu.Unlock()
		return r.ok, r.err
	}
	m.mu.Unlock()

	ok, cover, err := m.probe(ctx, serverName)
	cover.Proven = ok

	m.mu.Lock()
	m.results[serverName] = maskResult{ok: ok, err: err, at: m.now(), cover: cover}
	m.mu.Unlock()
	return ok, err
}

// Cover returns what the proof saw for a server name, and whether it was ever asked about.
//
// The second return is not decoration: a zero CoverCert and "no proof was attempted" are different
// facts, and publishing the first as if it were a measurement is the placeholder habit this project
// exists to avoid.
func (m *MaskingProver) Cover(serverName string) (CoverCert, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[serverName]
	if !ok {
		return CoverCert{}, false
	}
	return r.cover, true
}

// tlsVersionName renders a negotiated version as words. A number in a card is a number the reader
// has to look up.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return ""
}

// probe returns the verdict and what was seen on the way to it. The certificate is returned rather
// than logged because it is the evidence behind the verdict: see CoverCert.
func (m *MaskingProver) probe(ctx context.Context, serverName string) (bool, CoverCert, error) {
	ctx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()

	var seen CoverCert

	// The covered site is dialled through the same egress guard as everything else. A server
	// name pointing inward is not a covered site.
	addr, err := m.Resolver.Resolve(ctx, serverName)
	if err != nil {
		return false, seen, err
	}

	dial := m.dial
	if dial == nil {
		dial = func(ctx context.Context, a netip.Addr) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(443)))
		}
	}
	raw, err := dial(ctx, addr)
	if err != nil {
		return false, seen, err
	}
	defer raw.Close()

	// Verification is on. A self-signed or mismatched certificate means the name is not
	// really being served there, which is exactly what the check is for.
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if m.tlsConfig != nil {
		cfg = m.tlsConfig(serverName)
	}
	conn := tls.Client(raw, cfg)
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		return false, seen, err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false, seen, fmt.Errorf("masking: no certificate presented")
	}

	// Recorded here, after verification: a chain that failed to verify has told us nothing about
	// the covered site, and publishing what an unverified peer claimed would be publishing the
	// claim as the finding.
	leaf := state.PeerCertificates[0]
	seen = CoverCert{
		Issuer:     leaf.Issuer.CommonName,
		Subject:    leaf.Subject.CommonName,
		NotBefore:  leaf.NotBefore.UTC(),
		NotAfter:   leaf.NotAfter.UTC(),
		TLSVersion: tlsVersionName(state.Version),
	}

	// A modern cover site should also be speaking a modern protocol; anything less is a sign
	// the name is being served by something improvised.
	if state.Version < tls.VersionTLS12 {
		return false, seen, fmt.Errorf("masking: negotiated an obsolete TLS version")
	}
	return true, seen, nil
}

// Len is how many distinct server names were probed.
func (m *MaskingProver) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.results)
}
