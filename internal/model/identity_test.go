package model

import "testing"

func base() Identity {
	return Identity{
		Protocol:   ProtoVLESS,
		Server:     "node.example.com",
		Port:       443,
		Credential: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport:  TransportTCP,
		Security:   SecurityReality,
		SNI:        "www.microsoft.com",
		PublicKey:  "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd",
		ShortID:    "6ba85179e30d4fc2",
	}
}

// Every field that changes how a node is dialed must change its identity. The
// predecessor omitted SNI, public key and cipher, so distinct nodes merged and one was
// silently dropped at dedup — INV-21.
func TestEveryDialAffectingFieldChangesIdentity(t *testing.T) {
	original := base().Key()

	mutations := map[string]func(*Identity){
		"protocol":   func(i *Identity) { i.Protocol = ProtoTrojan },
		"server":     func(i *Identity) { i.Server = "other.example.com" },
		"port":       func(i *Identity) { i.Port = 8443 },
		"port range": func(i *Identity) { i.PortRange = "20000:30000" },
		"credential": func(i *Identity) { i.Credential = "00000000-0000-0000-0000-000000000000" },
		"method":     func(i *Identity) { i.Method = "aes-256-gcm" },
		"transport":  func(i *Identity) { i.Transport = TransportWebSocket },
		"security":   func(i *Identity) { i.Security = SecurityTLS },
		"sni":        func(i *Identity) { i.SNI = "www.apple.com" },
		"host":       func(i *Identity) { i.Host = "cdn.example.com" },
		"path":       func(i *Identity) { i.Path = "/ws" },
		"public key": func(i *Identity) { i.PublicKey = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" },
		"short id":   func(i *Identity) { i.ShortID = "0011223344556677" },
		"plugin":     func(i *Identity) { i.Plugin = "obfs-local" },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			id := base()
			mutate(&id)
			if id.Key() == original {
				t.Fatalf("changing %s did not change the identity", name)
			}
		})
	}
}

// Two Reality nodes identical except for SNI are the case the predecessor merged.
func TestRealityNodesDifferingOnlyBySNIAreDistinct(t *testing.T) {
	a, b := base(), base()
	b.SNI = "www.apple.com"
	if a.Key() == b.Key() {
		t.Fatal("Reality nodes differing only by SNI must not share an identity")
	}
}

// Shadowsocks nodes identical except for cipher are the other merge case.
func TestShadowsocksNodesDifferingOnlyByMethodAreDistinct(t *testing.T) {
	a := Identity{Protocol: ProtoShadowsocks, Server: "ss.example.com", Port: 8388,
		Credential: "hunter2", Method: "aes-256-gcm", Transport: TransportTCP}
	b := a
	b.Method = "chacha20-ietf-poly1305"
	if a.Key() == b.Key() {
		t.Fatal("Shadowsocks nodes differing only by cipher must not share an identity")
	}
}

// Length prefixing exists so that shifting a character across a field boundary cannot
// produce the same canonical form.
func TestFieldBoundariesCannotBeConfused(t *testing.T) {
	a := Identity{Protocol: ProtoTrojan, Server: "ab", Credential: "c"}
	b := Identity{Protocol: ProtoTrojan, Server: "a", Credential: "bc"}
	if a.Key() == b.Key() {
		t.Fatal("field boundaries are ambiguous: values shifted across fields collide")
	}
}

// Host and SNI are case-insensitive in DNS and TLS, so they must not fork identity.
func TestHostnameCaseDoesNotForkIdentity(t *testing.T) {
	a := base()
	b := base()
	b.Server = "NODE.Example.COM"
	b.SNI = "WWW.microsoft.COM"
	if a.Key() != b.Key() {
		t.Fatal("hostname case must not change identity")
	}
}

// The credential must never be recoverable from anything the system writes down.
func TestKeyDoesNotLeakTheCredential(t *testing.T) {
	id := base()
	for _, s := range []string{id.Key(), id.Short(), id.Endpoint()} {
		if contains(s, id.Credential) {
			t.Fatalf("credential leaked into %q", s)
		}
	}
}

func TestShortIsStableAndShort(t *testing.T) {
	id := base()
	if got := len(id.Short()); got != 8 {
		t.Fatalf("Short() length = %d, want 8", got)
	}
	if id.Short() != id.Short() {
		t.Fatal("Short() is not stable")
	}
}

func TestEndpointBracketsIPv6(t *testing.T) {
	id := Identity{Server: "2001:db8::1", Port: 443}
	if got, want := id.Endpoint(), "[2001:db8::1]:443"; got != want {
		t.Fatalf("Endpoint() = %q, want %q", got, want)
	}
	id = Identity{Server: "1.2.3.4", Port: 8080}
	if got, want := id.Endpoint(), "1.2.3.4:8080"; got != want {
		t.Fatalf("Endpoint() = %q, want %q", got, want)
	}
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
