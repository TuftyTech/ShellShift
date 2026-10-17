package tunnel

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/publish"
)

// INV-50. This is a stronger claim than the round-trip identity test, and it is the one that
// answers whether a client can actually use what we publish.
//
// Identity equality only says the two URIs name the same endpoint. It says nothing about the
// fields identity does not cover — fingerprint, ALPN, plugin options, obfuscation password —
// each of which changes how a client dials. A node can survive publication with the same
// identity and still be broken for the person who imports it.
//
// So the comparison is made at the only place that settles it: the configuration a client
// builds. Both the original node and the one recovered from our published URI are turned into
// sing-box outbound options and serialised. If those two documents are identical, then any
// client that behaves like sing-box dials both the same way.
func optionsJSON(t *testing.T, uri string) string {
	t.Helper()
	res, err := decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode %.60q: %v", uri, err)
	}
	opts, err := buildOptions(Target{Node: res.Node, Server: netip.MustParseAddr("203.0.113.10")}, Config{})
	if err != nil {
		t.Fatalf("options for %.60q: %v", uri, err)
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("marshal options: %v", err)
	}
	return string(raw)
}

func republish(t *testing.T, uri string) string {
	t.Helper()
	res, err := decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode %.60q: %v", uri, err)
	}
	out, err := publish.Encode(res.Node, "US | example | node")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out
}

// TestPublishedURIBuildsAnIdenticalClientConfiguration is the fidelity gate.
func TestPublishedURIBuildsAnIdenticalClientConfiguration(t *testing.T) {
	cases := []struct{ name, uri string }{
		{"vless reality with fingerprint", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=6ba8&fp=firefox"},
		{"vless reality custom alpn", "vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&alpn=h3"},
		{"vless tls vision", "vless://" + uuid + "@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=example.com&fp=safari"},
		{"vless ws host and path", "vless://" + uuid + "@example.com:443?type=ws&security=tls&host=front.example.com&path=%2Fws&fp=chrome"},
		{"vless grpc service name", "vless://" + uuid + "@example.com:443?type=grpc&security=tls&serviceName=Gun&sni=example.com"},
		{"vless httpupgrade", "vless://" + uuid + "@example.com:443?type=httpupgrade&security=tls&host=f.example.com&path=%2Fup"},
		{"vless http2 multi host", "vless://" + uuid + "@example.com:443?type=http&security=tls&host=a.example.com%2Cb.example.com&path=%2Fh"},

		{"trojan ws", "trojan://p4ss@example.com:443?type=ws&security=tls&host=f.example.com&path=%2Fws&fp=edge"},
		{"trojan tcp alpn", "trojan://p4ss@example.com:443?type=tcp&security=tls&sni=example.com&alpn=h2"},

		{"ss plain", "ss://aes-256-gcm:hunter2@example.com:8388"},
		{"ss 2022", "ss://2022-blake3-aes-256-gcm:" + psk32 + "@example.com:8388"},
		{"ss obfs plugin", "ss://aes-256-gcm:hunter2@example.com:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dexample.org"},
		{"ss v2ray plugin", "ss://aes-256-gcm:hunter2@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dexample.org"},

		{"hy2 salamander", "hysteria2://p4ss@example.com:443?obfs=salamander&obfs-password=shh&sni=example.com"},
		{"hy2 port hopping", "hysteria2://p4ss@example.com:443?mport=20000-30000&sni=example.com"},
		{"hy2 custom alpn", "hysteria2://p4ss@example.com:443?sni=example.com&alpn=h3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := optionsJSON(t, tc.uri)
			after := optionsJSON(t, republish(t, tc.uri))
			if before != after {
				t.Errorf("publication changed the configuration a client would build\n  before: %s\n  after:  %s\n  uri:    %s",
					before, after, republish(t, tc.uri))
			}
		})
	}
}

// The same gate against a corpus derived from a real published catalogue.
//
// The synthetic cases above cover the combinations somebody thought to write down. This one
// covers the combinations that actually occur: one line per distinct parameter shape found in
// 865 real published nodes, with credentials and hostnames replaced by synthetic values and
// every other parameter verbatim. Sanitising is not caution for its own sake — committing a
// real catalogue would make this repository the durable archive of other people credentials
// that the predecessor accidentally became.
func TestFidelityAgainstTheRealCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "corpus.txt"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}

	var checked, rejected int
	byReason := map[string]int{}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		res, derr := decode.Decode(line)
		if derr != nil {
			// A rejection here is a decision, not a failure: the corpus deliberately includes
			// shapes the policy refuses. What matters is that the reason is one we chose.
			reason, _ := decode.ReasonOf(derr)
			byReason[string(reason)]++
			rejected++
			continue
		}

		published, eerr := publish.Encode(res.Node, "US | example | node")
		if eerr != nil {
			t.Errorf("encode failed for a decodable node: %v", eerr)
			continue
		}
		again, derr2 := decode.Decode(published)
		if derr2 != nil {
			t.Errorf("our own published URI does not decode: %v\n  %s", derr2, published)
			continue
		}

		before, berr := buildOptions(Target{Node: res.Node, Server: netip.MustParseAddr("203.0.113.10")}, Config{})
		after, aerr := buildOptions(Target{Node: again.Node, Server: netip.MustParseAddr("203.0.113.10")}, Config{})
		if berr != nil || aerr != nil {
			t.Errorf("building options failed: before=%v after=%v", berr, aerr)
			continue
		}
		beforeJSON, _ := json.Marshal(before)
		afterJSON, _ := json.Marshal(after)
		if string(beforeJSON) != string(afterJSON) {
			t.Errorf("publication changed the client configuration\n  before: %s\n  after:  %s\n  uri:    %s",
				beforeJSON, afterJSON, published)
		}
		checked++
	}

	t.Logf("fidelity held for %d shapes; %d refused by policy: %v", checked, rejected, byReason)
	if checked < 40 {
		t.Fatalf("only %d shapes were checked: the corpus is not exercising the encoder", checked)
	}
}
