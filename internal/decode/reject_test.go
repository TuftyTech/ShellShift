package decode

import (
	"strings"
	"testing"
)

// vmessBadUUID is {"v":"2","ps":"x","add":"example.com","port":443,"id":"not-a-uuid",
// "net":"tcp"} base64-encoded without padding, precomputed because the table below is built
// before a *testing.T exists.
const vmessBadUUID = "eyJ2IjoiMiIsInBzIjoieCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6NDQzL" +
	"CJpZCI6Im5vdC1hLXV1aWQiLCJuZXQiOiJ0Y3AifQ"

// Every row is a case the predecessor suite asserted must yield nothing. Here each one
// additionally asserts *why* it was rejected, because a reason that silently changes is
// how a decoder regression hides as upstream churn.
func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name   string
		uri    string
		reason Reason
	}{
		// GHOST-004 and INV-02: the VLESS/VMess credential must be a UUID.
		{"vless malformed uuid", "vless://not-a-uuid@example.com:443?security=tls", ReasonBadUUID},
		{"vless missing uuid", "vless://@example.com:443?security=tls", ReasonMissingCredential},
		// The same rule inside a base64 payload, where it is invisible until decoded.
		{"vmess malformed uuid", "vmess://" + vmessBadUUID, ReasonBadUUID},

		// GHOST-002: hosts that cannot denote a public endpoint.
		{"loopback literal", "vless://" + validUUID + "@127.0.0.1:443?security=tls", ReasonBadHost},
		{"unspecified literal", "vless://" + validUUID + "@0.0.0.0:443?security=tls", ReasonBadHost},
		{"localhost name", "vless://" + validUUID + "@localhost:443?security=tls", ReasonBadHost},
		{"ipv6 loopback", "vless://" + validUUID + "@[::1]:443?security=tls", ReasonBadHost},
		{"private range", "vless://" + validUUID + "@192.168.1.10:443?security=tls", ReasonBadHost},
		{"link-local metadata", "vless://" + validUUID + "@169.254.169.254:80?security=tls", ReasonBadHost},
		{"mdns suffix", "vless://" + validUUID + "@printer.local:443?security=tls", ReasonBadHost},
		{"not a hostname", "vless://" + validUUID + "@nodots:443?security=tls", ReasonBadHost},

		// GHOST-003 and INV-29: a port we cannot read is a rejection, never a default.
		{"missing port", "vless://" + validUUID + "@example.com?security=tls", ReasonMissingPort},
		{"non-numeric port", "vless://" + validUUID + "@example.com:https?security=tls", ReasonBadPort},
		{"port out of range", "vless://" + validUUID + "@example.com:70000?security=tls", ReasonBadPort},
		{"port zero", "vless://" + validUUID + "@example.com:0?security=tls", ReasonBadPort},

		// GHOST-007: placeholder and honeypot markers.
		{"garbage marker in uri", "vless://" + validUUID + "@test1.example.com:443?security=tls", ReasonGarbageMarker},
		{"garbage marker uppercase", "vless://" + validUUID + "@PWN1337.example.com:443?security=tls", ReasonGarbageMarker},

		// INV-15: the Reality public key must decode to exactly 32 bytes.
		{"reality key too short", "vless://" + validUUID + "@example.com:443?security=reality&pbk=short", ReasonBadRealityKey},
		{"reality key missing", "vless://" + validUUID + "@example.com:443?security=reality", ReasonBadRealityKey},

		// GHOST-005 and INV-04: Trojan and Hysteria2 without a password are refused, and
		// Shadowsocks needs both halves of method:password.
		{"trojan without password", "trojan://@example.com:443?security=tls", ReasonMissingCredential},
		{"hysteria2 without password", "hy2://@example.com:443", ReasonMissingCredential},
		{"shadowsocks without password", "ss://aes-256-gcm:@example.com:8388", ReasonMissingCredential},
		{"shadowsocks without method", "ss://:pass@example.com:8388", ReasonMissingCredential},

		// GHOST-006, INV-05 and INV-06: the cipher allowlist is an allowlist, not a
		// blocklist, and 2022 ciphers additionally constrain the pre-shared key length.
		{"shadowsocks rc4", "ss://rc4-md5:pass@example.com:8388", ReasonUnsupportedCipher},
		{"shadowsocks 2022 wrong key length",
			"ss://2022-blake3-aes-128-gcm:c2hvcnQ=@example.com:8388", ReasonBadPSKLength},

		// INV-07: SIP003 outside the supported pair.
		{"unsupported sip003 plugin",
			"ss://aes-256-gcm:pass@example.com:8388?plugin=kcptun%3Bmode%3Dfast", ReasonUnsupportedPlugin},

		// INV-10: Hysteria2 obfuscation outside the single supported type.
		{"unsupported hysteria2 obfs",
			"hy2://p4ss@example.com:443?obfs=xor&obfs-password=x", ReasonUnsupportedPlugin},

		// INV-12: Hysteria v1 is not silently treated as v2.
		{"hysteria v1 scheme", "hysteria://p4ss@example.com:443", ReasonUnknownScheme},

		// GHOST-001: schemes we do not implement.
		{"unknown scheme", "ftp://example.com:21", ReasonUnknownScheme},
		{"no scheme separator", "example.com:443", ReasonNotAURI},
		{"empty", "", ReasonNotAURI},
		{"comment line", "# a comment", ReasonNotAURI},
		{"prose", "Here are some free proxies for you", ReasonNotAURI},

		// GHOST-011: plaintext without a transport that could carry it.
		{"plaintext vless over tcp",
			"vless://" + validUUID + "@example.com:80?security=none&type=tcp", ReasonPlaintextNoTunnel},

		// INV-09: a port range we cannot parse is not forwarded.
		{"inverted port range",
			"hy2://p4ss@example.com:443?mport=30000-20000", ReasonBadPortRange},
		{"garbage port range",
			"hy2://p4ss@example.com:443?mport=abc-def", ReasonBadPortRange},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.uri)
			if err == nil {
				t.Fatalf("Decode(%.60q) succeeded, want rejection %s", tc.uri, tc.reason)
			}
			got, ok := ReasonOf(err)
			if !ok {
				t.Fatalf("error carries no reason: %v", err)
			}
			if got != tc.reason {
				t.Fatalf("reason = %s, want %s (%v)", got, tc.reason, err)
			}
		})
	}
}

// The marker often appears only in the label inside the base64 payload, which is
// invisible until the payload is decoded (GHOST-007).
func TestGarbageMarkerInsideVMessLabel(t *testing.T) {
	uri := vmessURI(t, map[string]any{
		"add": "example.com", "port": 443, "id": validUUID,
		"net": "ws", "tls": "tls", "ps": "free-rootface-node",
	})
	_, err := Decode(uri)
	if err == nil {
		t.Fatal("a marker inside the vmess label must reject the node")
	}
	if r, _ := ReasonOf(err); r != ReasonGarbageMarker {
		t.Fatalf("reason = %s, want %s", r, ReasonGarbageMarker)
	}
}

// A credential must never appear in an error message: rejections are logged, and the
// predecessor put whole URIs into logs.
func TestRejectionDetailDoesNotEchoCredentials(t *testing.T) {
	const secret = "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b"
	_, err := Decode("vless://" + secret + "@127.0.0.1:443?security=tls")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("credential echoed in error: %v", err)
	}
}
