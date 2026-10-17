package tunnel

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/model"
)

// testAddr stands in for the address the egress guard would have vetted. Using a
// documentation-range address keeps the test from ever reaching a real host.
var testAddr = netip.MustParseAddr("203.0.113.10")

const (
	uuid = "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b"
	pbk  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	// 32 zero bytes, base64: a valid Shadowsocks-2022 pre-shared key.
	psk32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// This is INV-00 expressed as a test: validate equals ship.
//
// Every combination the decoder accepts must produce an outbound sing-box actually
// builds. In the predecessor a combination it refused prevented the whole batch process
// from binding, taking fifty nodes with it, and the only defence was a recursive split
// that still lost six or seven innocent nodes per poison one. Here a refusal costs one
// node — but a refusal that the decoder should have caught is still a bug, and this test
// is where it surfaces.
func TestEveryDecodableNodeConstructsAnOutbound(t *testing.T) {
	uris := []struct{ name, uri string }{
		// VLESS across transports and security modes.
		{"vless tcp reality", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=6ba85179e3&fp=chrome"},
		{"vless tcp reality empty sid", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=none"},
		{"vless tcp tls vision", "vless://" + uuid + "@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=example.com"},
		{"vless ws tls", "vless://" + uuid + "@example.com:443?type=ws&security=tls&host=front.example.com&path=%2Fws"},
		{"vless ws no tls", "vless://" + uuid + "@example.com:80?type=ws&security=none&host=front.example.com&path=%2Fws"},
		{"vless grpc tls", "vless://" + uuid + "@example.com:443?type=grpc&security=tls&serviceName=Gun&sni=example.com"},
		{"vless grpc tls empty service", "vless://" + uuid + "@example.com:443?type=grpc&security=tls&sni=example.com"},
		{"vless httpupgrade tls", "vless://" + uuid + "@example.com:443?type=httpupgrade&security=tls&host=front.example.com&path=%2Fup"},
		{"vless xhttp tls", "vless://" + uuid + "@example.com:443?type=xhttp&security=tls&host=front.example.com&path=%2Fx"},
		{"vless http2 tls", "vless://" + uuid + "@example.com:443?type=http&security=tls&host=a.example.com%2Cb.example.com&path=%2Fh"},
		{"vless raw alias", "vless://" + uuid + "@example.com:443?type=raw&security=tls&sni=example.com"},
		{"vless reality with alpn", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&alpn=h2%2Chttp%2F1.1"},

		// VMess.
		{"vmess ws tls", vmessLink(t, map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "ws", "tls": "tls", "path": "/w", "host": "front.example.com"})},
		{"vmess tcp tls", vmessLink(t, map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "tcp", "tls": "tls", "sni": "example.com"})},
		{"vmess ws plaintext", vmessLink(t, map[string]any{"add": "example.com", "port": 80, "id": uuid, "net": "ws", "tls": "", "path": "/w"})},
		{"vmess grpc tls", vmessLink(t, map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "grpc", "tls": "tls", "path": "Gun"})},
		{"vmess with alter id", vmessLink(t, map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "ws", "tls": "tls", "path": "/w", "aid": 4})},

		// Trojan.
		{"trojan tcp tls", "trojan://p4ss@example.com:443?security=tls&sni=example.com"},
		{"trojan ws tls", "trojan://p4ss@example.com:443?type=ws&security=tls&host=front.example.com&path=%2Fws"},
		{"trojan grpc tls", "trojan://p4ss@example.com:443?type=grpc&security=tls&serviceName=Gun"},
		{"trojan default security", "trojan://p4ss@example.com:443"},

		// Shadowsocks, including every accepted cipher family and the plugin path.
		{"ss aes-256-gcm", "ss://aes-256-gcm:hunter2@example.com:8388"},
		{"ss aes-128-gcm", "ss://aes-128-gcm:hunter2@example.com:8388"},
		{"ss chacha20", "ss://chacha20-ietf-poly1305:hunter2@example.com:8388"},
		{"ss xchacha20", "ss://xchacha20-ietf-poly1305:hunter2@example.com:8388"},
		{"ss 2022 aes-256", "ss://2022-blake3-aes-256-gcm:" + psk32 + "@example.com:8388"},
		{"ss 2022 chacha20", "ss://2022-blake3-chacha20-poly1305:" + psk32 + "@example.com:8388"},
		{"ss with obfs plugin", "ss://aes-256-gcm:hunter2@example.com:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dexample.org"},
		{"ss with v2ray plugin", "ss://aes-256-gcm:hunter2@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket"},

		// Hysteria2, including port hopping and obfuscation.
		{"hy2 plain", "hy2://p4ss@example.com:443?sni=example.com"},
		{"hy2 salamander", "hy2://p4ss@example.com:443?obfs=salamander&obfs-password=shh&sni=example.com"},
		{"hy2 port hopping", "hy2://p4ss@example.com:443?mport=20000-30000&sni=example.com"},
		{"hy2 multi range hopping", "hy2://p4ss@example.com:443?mport=20000-30000%2C40000-41000&sni=example.com"},
		{"hy2 with alpn", "hy2://p4ss@example.com:443?alpn=h3&sni=example.com"},
	}

	d := NewInProcess(Config{})
	defer d.Close()

	for _, tc := range uris {
		t.Run(tc.name, func(t *testing.T) {
			res, err := decode.Decode(tc.uri)
			if err != nil {
				t.Fatalf("decoder rejected a case it should accept: %v", err)
			}
			out, err := d.newOutbound(d.ctx, d.logger, Target{Node: res.Node, Server: testAddr})
			if err != nil {
				t.Fatalf("sing-box refused a node the decoder accepted: %v", err)
			}
			if out == nil {
				t.Fatal("constructor returned no outbound")
			}
			closeOutbound(out)
		})
	}
}

// INV-13 and INV-14. The host field is typed differently by every transport, and the
// predecessor called this a classic source of failure: a node that constructs cleanly still
// fails to connect when the authority lands in the wrong place.
//
// TestEveryDecodableNodeConstructsAnOutbound above proves these build. It cannot prove they
// build correctly — a websocket authority written to a host field instead of a header
// constructs perfectly and then fails the handshake at the far end. So the shapes are
// asserted here, one case per row of the table in invariants.md.
func TestTransportsTypeTheHostField(t *testing.T) {
	// websocket: the authority is a Host header, and the path defaults to "/".
	t.Run("websocket puts the authority in a header", func(t *testing.T) {
		tr := transportFor(t, "vless://"+uuid+"@example.com:443?type=ws&security=tls&host=front.example.com&path=%2Fws")
		if got := tr.WebsocketOptions.Headers["Host"]; len(got) != 1 || got[0] != "front.example.com" {
			t.Fatalf("Host header = %v, want [front.example.com]", got)
		}
		if tr.WebsocketOptions.Path != "/ws" {
			t.Fatalf("path = %q, want /ws", tr.WebsocketOptions.Path)
		}
	})
	t.Run("websocket path defaults to slash", func(t *testing.T) {
		tr := transportFor(t, "vless://"+uuid+"@example.com:443?type=ws&security=tls")
		if tr.WebsocketOptions.Path != "/" {
			t.Fatalf("path = %q, want /", tr.WebsocketOptions.Path)
		}
	})

	// grpc: the key is never omitted, and INV-14 back-fills it from path when the producer
	// wrote the service name there instead.
	t.Run("grpc carries the service name from serviceName", func(t *testing.T) {
		tr := transportFor(t, "vless://"+uuid+"@example.com:443?type=grpc&security=tls&serviceName=Gun&sni=example.com")
		if tr.GRPCOptions.ServiceName != "Gun" {
			t.Fatalf("service name = %q, want Gun", tr.GRPCOptions.ServiceName)
		}
	})
	t.Run("grpc back-fills the service name from path", func(t *testing.T) {
		tr := transportFor(t, "vless://"+uuid+"@example.com:443?type=grpc&security=tls&path=Gun&sni=example.com")
		if tr.GRPCOptions.ServiceName != "Gun" {
			t.Fatalf("service name = %q, want Gun back-filled from path (INV-14)",
				tr.GRPCOptions.ServiceName)
		}
	})
	t.Run("grpc keeps an empty service name as a value", func(t *testing.T) {
		tr := transportFor(t, "vless://"+uuid+"@example.com:443?type=grpc&security=tls&sni=example.com")
		if tr.GRPCOptions.ServiceName != "" {
			t.Fatalf("service name = %q, want empty", tr.GRPCOptions.ServiceName)
		}
	})

	// httpupgrade: host is a single string, and xhttp maps onto the same transport.
	t.Run("httpupgrade host is a string", func(t *testing.T) {
		for _, typ := range []string{"httpupgrade", "xhttp"} {
			tr := transportFor(t, "vless://"+uuid+"@example.com:443?type="+typ+
				"&security=tls&host=front.example.com&path=%2Fup")
			if tr.HTTPUpgradeOptions.Host != "front.example.com" {
				t.Fatalf("%s host = %q, want front.example.com", typ, tr.HTTPUpgradeOptions.Host)
			}
		}
	})

	// http/h2: host is a list, split on commas.
	t.Run("http2 host is a comma-split list", func(t *testing.T) {
		tr := transportFor(t, "vless://"+uuid+"@example.com:443?type=http&security=tls"+
			"&host=a.example.com%2Cb.example.com&path=%2Fh")
		if len(tr.HTTPOptions.Host) != 2 ||
			tr.HTTPOptions.Host[0] != "a.example.com" || tr.HTTPOptions.Host[1] != "b.example.com" {
			t.Fatalf("host = %v, want [a.example.com b.example.com]", tr.HTTPOptions.Host)
		}
	})

	// quic: bare, no options. Hysteria2 carries its own QUIC and gets no v2ray transport.
	t.Run("hysteria2 gets no v2ray transport", func(t *testing.T) {
		res, err := decode.Decode("hy2://p4ss@example.com:443?sni=example.com")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		tr, err := buildTransport(res.Node)
		if err != nil {
			t.Fatalf("buildTransport: %v", err)
		}
		if tr != nil {
			t.Fatalf("hysteria2 got a v2ray transport block: %+v", tr)
		}
	})
}

// transportFor decodes a URI and returns the transport block sing-box would be given.
func transportFor(t *testing.T, uri string) *option.V2RayTransportOptions {
	t.Helper()
	res, err := decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode %.60q: %v", uri, err)
	}
	tr, err := buildTransport(res.Node)
	if err != nil {
		t.Fatalf("buildTransport: %v", err)
	}
	if tr == nil {
		t.Fatalf("no transport block for %.60q", uri)
	}
	return tr
}

// INV-20. Reality spiderX is parsed and republished, and it is deliberately not handed to
// sing-box, which has no support for it.
//
// The predecessor had the same behaviour by accident and its note said to decide this
// consciously rather than inherit it. The decision is: carry it, because Xray-based clients use
// it and dropping it broke twelve nodes in the real corpus (INV-51); do not pass it, because
// there is nowhere to pass it to. Both halves are asserted here — the carrying half in
// publish.TestCarriedParametersSurvive, the not-passing half below.
func TestSpiderXNeverReachesTheOutbound(t *testing.T) {
	const uri = "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk +
		"&sid=6ba8&spx=%2FypOQfTdNbrZTBZF"
	res, err := decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// It survived decoding: this test would otherwise pass for the wrong reason.
	if res.Node.Carried["spx"] != "/ypOQfTdNbrZTBZF" {
		t.Fatalf("spx = %q after decoding, want it carried", res.Node.Carried["spx"])
	}

	opts, err := buildOptions(Target{Node: res.Node, Server: testAddr}, Config{})
	if err != nil {
		t.Fatalf("buildOptions: %v", err)
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"spx", "spiderX", "spider_x", "ypOQfTdNbrZTBZF"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("%q reached the sing-box options:\n%s", forbidden, raw)
		}
	}
}

// INV-48. The outbound is given a resolved address, never a hostname — and the hostname is not
// lost, it moves to the two places the far end actually checks.
//
// Handing sing-box a name makes the in-process outbound ask the context for a DNS transport:
// without one that is a nil dereference, and with one it means instantiating DNS, routing and
// service registries reachable from hostile input. Resolving once and dialing the pinned
// address is also what closes the DNS-rebinding window (INV-33).
func TestOutboundIsGivenAnAddressNotAName(t *testing.T) {
	// A node whose server is a hostname, with a distinct SNI and transport host so that each
	// can be told apart in the result.
	const uri = "vless://" + uuid + "@node.example.com:443?type=ws&security=tls" +
		"&sni=tls.example.com&host=front.example.com&path=%2Fws"
	res, err := decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	t.Run("a target with no resolved address is refused", func(t *testing.T) {
		if _, err := buildOptions(Target{Node: res.Node}, Config{}); err == nil {
			t.Fatal("options were built for a target carrying no address")
		}
	})

	t.Run("the dialed server is the address, and the name moves", func(t *testing.T) {
		opts, err := buildOptions(Target{Node: res.Node, Server: testAddr}, Config{})
		if err != nil {
			t.Fatalf("buildOptions: %v", err)
		}
		vless, ok := opts.(option.VLESSOutboundOptions)
		if !ok {
			t.Fatalf("options are %T, want VLESSOutboundOptions", opts)
		}
		if vless.Server != testAddr.String() {
			t.Fatalf("server = %q, want the resolved address %s", vless.Server, testAddr)
		}
		if strings.Contains(vless.Server, "example.com") {
			t.Fatalf("server = %q: a hostname reached the outbound", vless.Server)
		}
		// The name survives where the far end checks it: the TLS server name...
		if vless.TLS == nil || vless.TLS.ServerName != "tls.example.com" {
			t.Fatalf("TLS server name = %v, want tls.example.com", vless.TLS)
		}
		// ...and the transport Host header.
		got := vless.Transport.WebsocketOptions.Headers["Host"]
		if len(got) != 1 || got[0] != "front.example.com" {
			t.Fatalf("Host header = %v, want [front.example.com]", got)
		}
	})
}

// INV-19. A TLS-bearing node with no ALPN gets ["h2","http/1.1"], and a node that names its
// own ALPN keeps it. Plaintext gets none: an ALPN list without TLS is meaningless.
func TestALPNDefaultsForTLSBearingNodes(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want []string
	}{
		{"tls without alpn defaults", "vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com",
			[]string{"h2", "http/1.1"}},
		{"reality without alpn defaults", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk,
			[]string{"h2", "http/1.1"}},
		{"an explicit alpn is kept", "vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com&alpn=h3",
			[]string{"h3"}},
		{"plaintext gets none", "vless://" + uuid + "@example.com:80?type=ws&security=none&path=%2Fw", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := decode.Decode(tc.uri)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(res.Node.ALPN) != len(tc.want) {
				t.Fatalf("ALPN = %v, want %v", res.Node.ALPN, tc.want)
			}
			for i, want := range tc.want {
				if res.Node.ALPN[i] != want {
					t.Fatalf("ALPN = %v, want %v", res.Node.ALPN, tc.want)
				}
			}
			// The value must also reach the options sing-box is handed, not merely sit on
			// the node: that gap is what INV-50 exists to catch elsewhere.
			if tls := buildTLS(res.Node, Config{}); tls != nil && len(tc.want) > 0 {
				if len(tls.ALPN) != len(tc.want) {
					t.Fatalf("ALPN in options = %v, want %v", tls.ALPN, tc.want)
				}
			}
		})
	}
}

// INV-11. Hysteria2 is TLS by definition — there is no plaintext mode — and the predecessor
// paired that with insecure: true unconditionally. Here the TLS is real and verified.
func TestHysteria2AlwaysCarriesVerifiedTLS(t *testing.T) {
	for _, uri := range []string{
		"hy2://p4ss@example.com:443",
		"hy2://p4ss@example.com:443?sni=example.com",
		"hy2://p4ss@[2001:db8::1]:443", // IPv6 literal: the brackets must not reach the SNI
	} {
		res, err := decode.Decode(uri)
		if err != nil {
			t.Fatalf("decode %.50q: %v", uri, err)
		}
		if res.Node.Identity.Security != model.SecurityTLS {
			t.Fatalf("%.50q: security = %q, want tls", uri, res.Node.Identity.Security)
		}
		tls := buildTLS(res.Node, Config{})
		if tls == nil || !tls.Enabled {
			t.Fatalf("%.50q: hysteria2 must carry an enabled TLS block", uri)
		}
		if tls.Insecure {
			t.Fatalf("%.50q: certificate verification must stay on (INV-30)", uri)
		}
		if strings.ContainsAny(tls.ServerName, "[]") {
			t.Fatalf("%.50q: server name %q still carries brackets", uri, tls.ServerName)
		}
	}
}

// INV-30. Certificate verification is on unless something explicitly asks otherwise,
// and nothing in the normal path does.
func TestTLSVerificationIsOnByDefault(t *testing.T) {
	res, err := decode.Decode("vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	tls := buildTLS(res.Node, Config{})
	if tls == nil {
		t.Fatal("expected a TLS block")
	}
	if tls.Insecure {
		t.Fatal("certificate verification must be enabled by default")
	}
	if tls.ServerName != "example.com" {
		t.Fatalf("server name = %q", tls.ServerName)
	}
}

// INV-08. Shadowsocks takes neither a transport nor a TLS block; setting either is a
// configuration rejection.
func TestShadowsocksCarriesNoTransportOrTLS(t *testing.T) {
	res, err := decode.Decode("ss://aes-256-gcm:hunter2@example.com:8388")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tls := buildTLS(res.Node, Config{}); tls != nil {
		t.Fatal("shadowsocks must carry no TLS block")
	}
	tr, err := buildTransport(res.Node)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if tr != nil {
		t.Fatal("shadowsocks must carry no transport block")
	}
}

func vmessLink(t *testing.T, payload map[string]any) string {
	t.Helper()
	return encodeVMess(t, payload)
}

var _ = model.ProtoVLESS
