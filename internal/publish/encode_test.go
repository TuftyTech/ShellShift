package publish

import (
	"strings"
	"testing"

	"github.com/tuftytech/shellshift/internal/decode"
)

func TestVMessRoundTripPreservesIdentity(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"ws tls", map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "ws", "tls": "tls", "host": "f.example.com", "path": "/w"}},
		{"tcp tls", map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "tcp", "tls": "tls", "sni": "example.com"}},
		{"grpc tls", map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "grpc", "tls": "tls", "path": "Gun"}},
		{"with alter id", map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "ws", "tls": "tls", "path": "/w", "aid": 4}},
		{"plaintext ws", map[string]any{"add": "example.com", "port": 80, "id": uuid, "net": "ws", "tls": "", "path": "/w"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err := decode.Decode(vmessURI(t, tc.payload))
			if err != nil {
				t.Fatalf("first decode: %v", err)
			}
			published, err := Encode(first.Node, "US | example | node")
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			second, err := decode.Decode(published)
			if err != nil {
				t.Fatalf("re-decode: %v\n  published: %s", err, published)
			}
			if first.Node.Key() != second.Node.Key() {
				t.Errorf("identity changed\n  before: %+v\n  after:  %+v",
					first.Node.Identity, second.Node.Identity)
			}
			if first.Node.AlterID != second.Node.AlterID {
				t.Errorf("alterId changed: %d -> %d", first.Node.AlterID, second.Node.AlterID)
			}
		})
	}
}

// INV-38. A published URI must never tell a client to skip certificate verification. The
// predecessor set this on every TLS node and shipped it: 229 of 865 published nodes
// carried it.
func TestPublishedURIsNeverDisableVerification(t *testing.T) {
	uris := []string{
		"vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com&allowInsecure=1&insecure=1",
		"trojan://p4ss@example.com:443?security=tls&sni=example.com&allowInsecure=1",
		"hysteria2://p4ss@example.com:443?sni=example.com&insecure=1",
	}
	for _, uri := range uris {
		t.Run(uri[:12], func(t *testing.T) {
			res, err := decode.Decode(uri)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			published, err := Encode(res.Node, "node")
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			lower := strings.ToLower(published)
			for _, bad := range []string{"allowinsecure", "insecure=1"} {
				if strings.Contains(lower, bad) {
					t.Fatalf("published URI carries %q: %s", bad, published)
				}
			}
		})
	}
}

// PERF-041. Published output must be byte-stable under regeneration from unchanged input.
// The predecessor re-sorted its subscription files by speed every run, which changed line
// order globally and defeated delta compression on 406 KB of new objects per run.
func TestEncodingIsDeterministic(t *testing.T) {
	res, err := decode.Decode("vless://" + uuid + "@example.com:443?type=ws&security=reality&pbk=" + pbk +
		"&sid=ab&host=f.example.com&path=%2Fws&fp=firefox&alpn=h3")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	first, err := Encode(res.Node, "label")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, aerr := Encode(res.Node, "label")
		if aerr != nil {
			t.Fatalf("encode: %v", aerr)
		}
		if again != first {
			t.Fatalf("encoding is not deterministic:\n  %s\n  %s", first, again)
		}
	}
}

// INV-26. Reality carries keys whose empty value still means something, so they survive
// serialisation rather than being dropped.
func TestEmptyButMeaningfulKeysSurvive(t *testing.T) {
	res, err := decode.Decode("vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=none")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	published, err := Encode(res.Node, "n")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(published, "sid=") {
		t.Fatalf("the short id key must be present even when empty: %s", published)
	}
}

// A space must be percent-encoded rather than written as a plus sign: several clients read
// the plus literally, which is why the escaping is hand-written instead of delegated.
func TestSpacesAreNotEncodedAsPlus(t *testing.T) {
	res, err := decode.Decode("vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	published, err := Encode(res.Node, "US | my node")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	label := published[strings.LastIndex(published, "#")+1:]
	if strings.Contains(label, "+") {
		t.Fatalf("label encodes a space as plus: %s", label)
	}
	if !strings.Contains(label, "%20") {
		t.Fatalf("label does not percent-encode the space: %s", label)
	}
}

// INV-23. Deduplication must be blind to the human-readable label.
//
// The predecessor achieved this for VMess by decoding the payload, deleting "ps", re-serialising
// canonically and re-encoding. ShellShift gets it structurally and for every protocol at once:
// the label is parsed, used to detect garbage markers, and never stored on the node, so it
// cannot reach the identity. That is worth a test precisely because it is structural — the
// property would be lost silently by adding a label field to Identity.
func TestIdentityIsBlindToTheLabel(t *testing.T) {
	cases := []struct{ name, a, b string }{
		{
			"vmess ps differs",
			vmessURI(t, map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "tcp",
				"tls": "tls", "sni": "example.com", "ps": "🇳🇱 NL-01 | fast"}),
			vmessURI(t, map[string]any{"add": "example.com", "port": 443, "id": uuid, "net": "tcp",
				"tls": "tls", "sni": "example.com", "ps": "renamed by the aggregator"}),
		},
		{
			"vless fragment differs",
			"vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com#NL%20fast",
			"vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com#DE%20slow",
		},
		{
			"a fragment against no fragment at all",
			"trojan://p4ss@example.com:443?security=tls&sni=example.com#labelled",
			"trojan://p4ss@example.com:443?security=tls&sni=example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := decode.Decode(tc.a)
			if err != nil {
				t.Fatalf("decode a: %v", err)
			}
			b, err := decode.Decode(tc.b)
			if err != nil {
				t.Fatalf("decode b: %v", err)
			}
			if a.Node.Key() != b.Node.Key() {
				t.Fatalf("the label forked identity:\n  %s\n  %s", a.Node.Key(), b.Node.Key())
			}
		})
	}
}

// INV-25. Percent-encoding uses a safe set per key, because clients disagree about what they
// will accept. These sets were paid for against real clients, so a change that looks like
// tidying is a change in client compatibility.
func TestPercentEncodingUsesPerKeySafeSets(t *testing.T) {
	cases := []struct {
		name, uri, want string
	}{
		// Reality keys are base64url and must not be escaped: an escaped "-" or "_" is a
		// different key to a client that does not unescape before decoding.
		{"reality public key is not escaped",
			"vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk,
			"pbk=" + pbk},
		// flow, fp, type and security are enumerated values with no characters to escape.
		{"flow is not escaped",
			"vless://" + uuid + "@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=example.com",
			"flow=xtls-rprx-vision"},
		// A path is escaped completely, slashes included.
		{"path is fully escaped",
			"vless://" + uuid + "@example.com:443?type=ws&security=tls&path=%2Fa%2Fb&host=f.example.com",
			"path=%2Fa%2Fb"},
		// A host keeps the characters a hostname is made of.
		{"host keeps dots and dashes",
			"vless://" + uuid + "@example.com:443?type=ws&security=tls&host=a-b.example.com&path=%2Fw",
			"host=a-b.example.com"},
		// An ALPN list keeps its comma and the slash inside "http/1.1". The value here is
		// deliberately not the default h2,http/1.1, which publication omits because the
		// decoder supplies it again on the way back in.
		{"alpn keeps its separators",
			"vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com&alpn=h3%2Chttp%2F1.1",
			"alpn=h3,http/1.1"},
		// A gRPC service name keeps a slash: it is a path-shaped identifier.
		{"service name keeps a slash",
			"vless://" + uuid + "@example.com:443?type=grpc&security=tls&serviceName=a%2Fb&sni=example.com",
			"serviceName=a/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := decode.Decode(tc.uri)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			published, err := Encode(res.Node, "n")
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !strings.Contains(published, tc.want) {
				t.Fatalf("published URI does not contain %q:\n  %s", tc.want, published)
			}
		})
	}
}

// INV-27. Base64 in published output carries no padding, and an IPv6 host is bracketed.
//
// Padding is not cosmetic: several clients concatenate the payload with other text before
// decoding, and a "=" mid-string ends the decode early.
func TestPublishedBase64CarriesNoPadding(t *testing.T) {
	// A Shadowsocks credential whose method:password length is not a multiple of three, so
	// unpadded and padded encodings actually differ.
	res, err := decode.Decode("ss://aes-256-gcm:hunter2@example.com:8388")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	published, err := Encode(res.Node, "n")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cred := strings.TrimPrefix(published, "ss://")
	if i := strings.Index(cred, "@"); i >= 0 {
		cred = cred[:i]
	}
	if strings.Contains(cred, "=") || strings.Contains(cred, "%3D") {
		t.Fatalf("the shadowsocks credential carries padding: %s", published)
	}

	// VMess is a base64 payload in its entirety.
	vm, err := decode.Decode(vmessURI(t, map[string]any{
		"add": "example.com", "port": 443, "id": uuid, "net": "tcp", "tls": "tls", "sni": "example.com",
	}))
	if err != nil {
		t.Fatalf("decode vmess: %v", err)
	}
	pubVM, err := Encode(vm.Node, "n")
	if err != nil {
		t.Fatalf("encode vmess: %v", err)
	}
	if strings.Contains(strings.TrimPrefix(pubVM, "vmess://"), "=") {
		t.Fatalf("the vmess payload carries padding: %s", pubVM)
	}

	// An IPv6 host must be bracketed in the authority, or the port cannot be told from the
	// address.
	v6, err := decode.Decode("vless://" + uuid + "@[2001:db8::1]:443?type=tcp&security=tls&sni=example.com")
	if err != nil {
		t.Fatalf("decode ipv6: %v", err)
	}
	pubV6, err := Encode(v6.Node, "n")
	if err != nil {
		t.Fatalf("encode ipv6: %v", err)
	}
	if !strings.Contains(pubV6, "@[2001:db8::1]:443") {
		t.Fatalf("the ipv6 host is not bracketed: %s", pubV6)
	}
}

// INV-51. Carried parameters survive publication, and they travel by a named list rather than
// an unbounded bag. Measurement is what put this test here: republishing 100 distinct parameter
// shapes from a real catalogue dropped a Reality spiderX value on twelve of them — a value
// sing-box ignores and Xray-based clients use, so the node survived our pipeline and would have
// stopped working in the visitor client.
func TestCarriedParametersSurvive(t *testing.T) {
	cases := []struct{ name, uri, key, want string }{
		{"reality spiderx", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&spx=%2FypOQfTdNbrZTBZF", "spx", "/ypOQfTdNbrZTBZF"},
		{"grpc authority", "vless://" + uuid + "@example.com:443?type=grpc&security=tls&serviceName=Gun&authority=front.example.com", "authority", "front.example.com"},
		{"packet encoding", "vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com&packetEncoding=xudp", "packetEncoding", "xudp"},
		{"shadowsocks prefix", "ss://aes-256-gcm:pw@example.com:8388?prefix=POST%20abc", "prefix", "POST abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := decode.Decode(tc.uri)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			published, err := Encode(res.Node, "label")
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got := queryOf(published)[strings.ToLower(tc.key)]
			if got != tc.want {
				t.Fatalf("%s = %q after publication, want %q\n  %s", tc.key, got, tc.want, published)
			}
		})
	}
}

// Real values are kilobytes, so the per-parameter bounds allow kilobytes; the total bound is what
// stops a hostile source attaching the maximum of every carried key to every node it publishes.
func TestLargeCarriedValuesSurviveButTheTotalIsBounded(t *testing.T) {
	// An ECH configuration list of the size that actually occurs.
	large := strings.Repeat("A", 2300)
	res, err := decode.Decode("vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com&ech=" + large)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Node.Carried["ech"] != large {
		t.Fatalf("a 2.3 KB ECH value must survive, got %d bytes", len(res.Node.Carried["ech"]))
	}

	// Every carried key at its maximum must not all fit: the total bound has to bite.
	huge := strings.Repeat("B", 4096)
	uri := "vless://" + uuid + "@example.com:443?type=tcp&security=tls&sni=example.com" +
		"&ech=" + huge + "&pqv=" + huge + "&spx=" + strings.Repeat("C", 256)
	res, err = decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	total := 0
	for k, v := range res.Node.Carried {
		total += len(k) + len(v)
	}
	if total > 8192 {
		t.Fatalf("carried payload is %d bytes, the bound is 8192", total)
	}
	// The small numerous parameters are the ones worth keeping when something has to go.
	if res.Node.Carried["spx"] == "" {
		t.Fatal("trimming should drop the largest values, not the smallest")
	}
}
