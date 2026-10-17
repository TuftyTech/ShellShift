package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

// coverServer is a TLS server presenting a certificate for one name, with values a test can
// assert exactly. It exists because the prover's dial and tlsConfig hooks were written to be
// injectable and then never injected by any test — the comment at masking.go said so — which left
// the one thing the masking proof actually reads, the certificate, untested.
func coverServer(t *testing.T, name string, from, to time.Time) (addr netip.AddrPort, roots *x509.CertPool) {
	t.Helper()

	// A CA and a leaf signed by it, not one self-signed certificate: a real covered site presents
	// a chain, and the card's whole point is that the issuer is somebody other than the subject.
	// x509.CreateCertificate takes the issuer name from the parent's subject, so a self-signed
	// certificate cannot express that distinction at all.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cover Test CA"},
		NotBefore:             from.Add(-time.Hour),
		NotAfter:              to.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Cover Ltd"}},
		NotBefore:    from,
		NotAfter:     to,
		DNSNames:     []string{name},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots = x509.NewCertPool()
	roots.AddCert(ca)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leaf,
		}},
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// The prover only needs the handshake, so completing it and closing is the whole
			// server.
			go func() {
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				_ = conn.Close()
			}()
		}
	}()

	tcp := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(tcp.Port)), roots
}

// proverFor builds a prover that reaches the local cover server instead of the internet.
//
// The resolver answers with a public address and the dial hook ignores it. That is deliberate: the
// egress guard refuses loopback on purpose — a server name resolving inward is not a covered site,
// it is an SSRF — so a test that wanted the guard to allow 127.0.0.1 would be testing a weakened
// guard. Redirecting the socket instead leaves every policy check exactly as it runs in production.
func proverFor(t *testing.T, ap netip.AddrPort, roots *x509.CertPool) *MaskingProver {
	t.Helper()
	m := NewMaskingProver(&Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}})
	m.dial = func(ctx context.Context, _ netip.Addr) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ap.String())
	}
	m.tlsConfig = func(serverName string) *tls.Config {
		return &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return m
}

// The certificate the proof already fetched stops being thrown away.
//
// Proving masking means opening a TLS connection to the covered site and verifying the chain, so
// the issuer, the name on the certificate, its validity window and the negotiated TLS version are
// all in hand at that moment — and the prover discarded every one of them, keeping a single
// boolean. The node card is supposed to answer "what is this node pretending to be", and a
// boolean cannot: "masking proven" and "masking proven by a Let's Encrypt certificate for
// www.microsoft.com valid until March" are different amounts of evidence.
func TestTheCoverCertificateIsKept(t *testing.T) {
	const name = "cover.example.com"
	from := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	to := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)

	ap, roots := coverServer(t, name, from, to)
	m := proverFor(t, ap, roots)

	ok, err := m.Prove(context.Background(), name)
	if err != nil || !ok {
		t.Fatalf("Prove(%q) = %v, %v; the local cover server should satisfy it", name, ok, err)
	}

	cover, found := m.Cover(name)
	if !found {
		t.Fatal("the prover kept no certificate for a name it just proved")
	}
	if cover.Issuer != "Cover Test CA" {
		t.Errorf("issuer = %q, want %q", cover.Issuer, "Cover Test CA")
	}
	if cover.Subject != name {
		t.Errorf("subject = %q, want %q", cover.Subject, name)
	}
	if !cover.NotBefore.Equal(from) || !cover.NotAfter.Equal(to) {
		t.Errorf("validity = %v..%v, want %v..%v", cover.NotBefore, cover.NotAfter, from, to)
	}
	if cover.TLSVersion != "TLS 1.3" {
		t.Errorf("tls = %q, want TLS 1.3", cover.TLSVersion)
	}
	if !cover.Proven {
		t.Error("the record must say the proof succeeded")
	}

	// A name nobody asked about has no record. An empty CoverCert would publish a certificate
	// that was never seen, which is the placeholder this project refuses everywhere else.
	if _, found := m.Cover("never-asked.example.org"); found {
		t.Error("an unprobed name must have no record at all")
	}
}

// A refused proof still records what happened, without inventing a certificate.
func TestAFailedProofRecordsNoCertificate(t *testing.T) {
	ap, roots := coverServer(t, "cover.example.com", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m := proverFor(t, ap, roots)

	// The server presents a certificate for cover.example.com, so a different name fails
	// verification — exactly the case the class is about: a node naming a site it cannot serve.
	if ok, err := m.Prove(context.Background(), "other.example.com"); ok || err == nil {
		t.Fatalf("Prove(other) = %v, %v; want a refusal", ok, err)
	}
	cover, found := m.Cover("other.example.com")
	if !found {
		t.Fatal("a refusal is a result and must be recorded")
	}
	if cover.Proven {
		t.Error("a refused proof must not be recorded as proven")
	}
	if cover.Subject != "" || cover.Issuer != "" {
		t.Errorf("a failed handshake produced a certificate: %+v", cover)
	}
}
