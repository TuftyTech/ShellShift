package publish

import (
	"testing"

	"github.com/tuftytech/shellshift/internal/decode"
)

// This is the test that makes the predecessor defining structural defect impossible.
//
// There, protocol rules lived in three separate implementations — one deciding what a node
// is, one deciding what the engine sees, one deciding what the user client gets — and the
// project own notes warned that changing one without the others would make them disagree.
// They already had: a VMess Reality node was verified as Reality and published as
// ordinary TLS.
//
// Here there is one description and two projections of it, and this test fails the moment
// they diverge: decode a URI, publish it, decode the result, and the identity must be
// unchanged.
func TestURIRoundTripPreservesIdentity(t *testing.T) {
	uris := []struct{ name, uri string }{
		{"vless tcp reality", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=6ba85179e3&fp=chrome"},
		{"vless reality empty sid", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=none&fp=chrome"},
		{"vless tcp tls vision", "vless://" + uuid + "@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=example.com"},
		{"vless ws tls", "vless://" + uuid + "@example.com:443?type=ws&security=tls&host=front.example.com&path=%2Fws&sni=front.example.com"},
		{"vless ws deep path", "vless://" + uuid + "@example.com:443?type=ws&security=tls&path=%2Fa%2Fb&host=f.example.com"},
		{"vless grpc tls", "vless://" + uuid + "@example.com:443?type=grpc&security=tls&serviceName=Gun&sni=example.com"},
		{"vless httpupgrade", "vless://" + uuid + "@example.com:443?type=httpupgrade&security=tls&host=f.example.com&path=%2Fup"},
		{"vless http2 multi host", "vless://" + uuid + "@example.com:443?type=http&security=tls&host=a.example.com%2Cb.example.com&path=%2Fh"},
		{"vless ipv6", "vless://" + uuid + "@[2001:4860:4860::8888]:443?type=tcp&security=tls&sni=example.com"},
		{"vless custom alpn", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&alpn=h3"},

		{"trojan tcp tls", "trojan://p4ss@example.com:443?type=tcp&security=tls&sni=example.com"},
		{"trojan ws tls", "trojan://p4ss@example.com:443?type=ws&security=tls&host=f.example.com&path=%2Fws"},
		{"trojan password with symbols", "trojan://p%40ss%3Aw%2Frd@example.com:443?type=tcp&security=tls&sni=example.com"},

		{"ss aes-256-gcm", "ss://aes-256-gcm:hunter2@example.com:8388"},
		{"ss 2022", "ss://2022-blake3-aes-256-gcm:" + psk + "@example.com:8388"},
		{"ss with plugin", "ss://aes-256-gcm:hunter2@example.com:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dexample.org"},

		{"hy2 plain", "hysteria2://p4ss@example.com:443?sni=example.com"},
		{"hy2 salamander", "hysteria2://p4ss@example.com:443?obfs=salamander&obfs-password=shh&sni=example.com"},
		{"hy2 port hopping", "hysteria2://p4ss@example.com:443?mport=20000-30000&sni=example.com"},
	}

	for _, tc := range uris {
		t.Run(tc.name, func(t *testing.T) {
			first, err := decode.Decode(tc.uri)
			if err != nil {
				t.Fatalf("first decode: %v", err)
			}
			published, err := Encode(first.Node, "US | example | node")
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			second, err := decode.Decode(published)
			if err != nil {
				t.Fatalf("re-decoding the published URI failed: %v\n  published: %s", err, published)
			}
			if first.Node.Key() != second.Node.Key() {
				t.Errorf("identity changed through publication\n  before: %+v\n  after:  %+v\n  uri:    %s",
					first.Node.Identity, second.Node.Identity, published)
			}
			if first.Node.Flow != second.Node.Flow {
				t.Errorf("flow changed: %q -> %q", first.Node.Flow, second.Node.Flow)
			}
			if first.Node.Obfuscation != second.Node.Obfuscation {
				t.Errorf("obfuscation changed: %q -> %q", first.Node.Obfuscation, second.Node.Obfuscation)
			}
		})
	}
}
