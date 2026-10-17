package decode

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tuftytech/shellshift/internal/model"
)

// Constants carried over from the predecessor suite so that the ported cases are
// literally the same inputs, not paraphrases of them.
const (
	validUUID = "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b"
	// 32 zero-derived bytes rendered as 43 base64url characters: passes both the
	// length bound and the decoded-size check (INV-15).
	validPBK = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

func vmessURI(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal vmess payload: %v", err)
	}
	return "vmess://" + strings.TrimRight(base64.StdEncoding.EncodeToString(raw), "=")
}

func mustDecode(t *testing.T, uri string) model.Node {
	t.Helper()
	res, err := Decode(uri)
	if err != nil {
		t.Fatalf("Decode(%.70q) failed: %v", uri, err)
	}
	return res.Node
}

// --- valid inputs -------------------------------------------------------------

func TestDecodeValid(t *testing.T) {
	cases := []struct {
		name  string
		uri   string
		check func(t *testing.T, n model.Node)
	}{
		{
			name: "vless tcp reality",
			uri: "vless://" + validUUID + "@example.com:443" +
				"?type=tcp&security=reality&pbk=" + validPBK + "&sid=6ba85179e3&fp=chrome",
			check: func(t *testing.T, n model.Node) {
				want := model.Identity{
					Protocol: model.ProtoVLESS, Server: "example.com", Port: 443,
					Credential: validUUID, Transport: model.TransportTCP,
					Security: model.SecurityReality, PublicKey: validPBK,
					ShortID: "6ba85179e3",
				}
				if n.Identity != want {
					t.Errorf("identity =\n  %+v\nwant\n  %+v", n.Identity, want)
				}
				if n.Fingerprint != "chrome" {
					t.Errorf("fingerprint = %q, want chrome", n.Fingerprint)
				}
				// Reality must not borrow the server address as a server name.
				if n.Identity.SNI != "" {
					t.Errorf("SNI = %q, want empty for reality without sni", n.Identity.SNI)
				}
			},
		},
		{
			name: "vless ws tls with host and path",
			uri: "vless://" + validUUID + "@cdn.example.com:443" +
				"?type=ws&security=tls&host=front.example.com&path=%2Fws&sni=front.example.com",
			check: func(t *testing.T, n model.Node) {
				if n.Identity.Transport != model.TransportWebSocket {
					t.Errorf("transport = %q", n.Identity.Transport)
				}
				if n.Identity.Path != "/ws" {
					t.Errorf("path = %q, want /ws", n.Identity.Path)
				}
				if n.Identity.Host != "front.example.com" {
					t.Errorf("host = %q", n.Identity.Host)
				}
				if n.Identity.SNI != "front.example.com" {
					t.Errorf("sni = %q", n.Identity.SNI)
				}
			},
		},
		{
			name: "vless grpc service name falls back to path",
			uri: "vless://" + validUUID + "@grpc.example.com:443" +
				"?type=grpc&security=tls&path=GunService",
			check: func(t *testing.T, n model.Node) {
				if n.Identity.Transport != model.TransportGRPC {
					t.Errorf("transport = %q", n.Identity.Transport)
				}
				// The gRPC service name doubles as the path; sing-box needs the key
				// present, so an empty value would still be a value.
				if n.Identity.Path != "GunService" {
					t.Errorf("service name = %q, want GunService", n.Identity.Path)
				}
			},
		},
		{
			name: "trojan tls",
			uri:  "trojan://s3cret@trojan.example.com:8443?security=tls&sni=trojan.example.com",
			check: func(t *testing.T, n model.Node) {
				if n.Identity.Protocol != model.ProtoTrojan {
					t.Errorf("protocol = %q", n.Identity.Protocol)
				}
				if n.Identity.Credential != "s3cret" {
					t.Errorf("credential = %q", n.Identity.Credential)
				}
			},
		},
		{
			name: "trojan defaults to tls when the parameter is absent",
			uri:  "trojan://s3cret@trojan.example.com:443",
			check: func(t *testing.T, n model.Node) {
				if n.Identity.Security != model.SecurityTLS {
					t.Errorf("security = %q, want tls", n.Identity.Security)
				}
			},
		},
		{
			name: "shadowsocks plaintext credential",
			uri:  "ss://aes-256-gcm:hunter2@ss.example.com:8388",
			check: func(t *testing.T, n model.Node) {
				if n.Identity.Method != "aes-256-gcm" {
					t.Errorf("method = %q", n.Identity.Method)
				}
				if n.Identity.Credential != "hunter2" {
					t.Errorf("credential = %q", n.Identity.Credential)
				}
				// Shadowsocks takes neither a transport nor a TLS block (INV-08).
				if n.Identity.Transport != model.TransportTCP {
					t.Errorf("transport = %q, want tcp", n.Identity.Transport)
				}
				if n.Identity.Security != model.SecurityNone {
					t.Errorf("security = %q, want none", n.Identity.Security)
				}
			},
		},
		{
			name: "hysteria2 via hy2 abbreviation",
			uri:  "hy2://p4ss@hy2.example.com:443?sni=hy2.example.com",
			check: func(t *testing.T, n model.Node) {
				if n.Identity.Protocol != model.ProtoHysteria2 {
					t.Errorf("protocol = %q", n.Identity.Protocol)
				}
				if n.Identity.Transport != model.TransportQUIC {
					t.Errorf("transport = %q, want quic", n.Identity.Transport)
				}
			},
		},
		{
			name: "hysteria2 full scheme with salamander",
			uri:  "hysteria2://p4ss@hy2.example.com:443?obfs=salamander&obfs-password=shh&sni=a.example.com",
			check: func(t *testing.T, n model.Node) {
				if n.Obfuscation != model.Hysteria2Obfuscation {
					t.Errorf("obfuscation = %q", n.Obfuscation)
				}
				if n.ObfuscationPassword != "shh" {
					t.Errorf("obfuscation password = %q", n.ObfuscationPassword)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, mustDecode(t, tc.uri))
		})
	}
}
