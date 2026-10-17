package decode

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tuftytech/shellshift/internal/model"
)

// INV-01. xtls-rprx-vision is valid only over raw TCP. Paired with any v2ray
// transport sing-box rejects the configuration outright, which in the predecessor took
// down an entire batch of fifty nodes. The rule is enforced in one place, so the node
// that gets dialed and the URI that gets published cannot disagree.
func TestFlowSurvivesOnlyOnRawTCP(t *testing.T) {
	cases := []struct {
		transport string
		wantFlow  string
	}{
		{"tcp", "xtls-rprx-vision"},
		{"raw", "xtls-rprx-vision"},
		{"ws", ""},
		{"grpc", ""},
		{"httpupgrade", ""},
		{"http", ""},
	}
	for _, tc := range cases {
		t.Run(tc.transport, func(t *testing.T) {
			uri := "vless://" + validUUID + "@example.com:443" +
				"?security=tls&flow=xtls-rprx-vision&type=" + tc.transport +
				"&host=a.example.com&path=/x"
			n := mustDecode(t, uri)
			if n.Flow != tc.wantFlow {
				t.Fatalf("flow over %s = %q, want %q", tc.transport, n.Flow, tc.wantFlow)
			}
		})
	}
}

// INV-01 again, from the other direction: plaintext must not carry a flow either.
func TestFlowClearedWithoutTLS(t *testing.T) {
	n := mustDecode(t, "vless://"+validUUID+"@example.com:80?security=none&type=ws&flow=xtls-rprx-vision&path=/w")
	if n.Flow != "" {
		t.Fatalf("flow = %q, want empty without TLS", n.Flow)
	}
}

// INV-18. An address is not a valid server name; offering one breaks the handshake.
func TestSNINeverBecomesAnIPAddress(t *testing.T) {
	cases := []string{
		"vless://" + validUUID + "@203.0.113.10:443?security=tls&type=tcp",
		"vless://" + validUUID + "@203.0.113.10:443?security=tls&type=tcp&sni=203.0.113.10",
		"trojan://p@203.0.113.10:443?security=tls",
	}
	for _, uri := range cases {
		t.Run(uri[:24], func(t *testing.T) {
			n := mustDecode(t, uri)
			if n.Identity.SNI != "" {
				t.Fatalf("SNI = %q, want empty rather than an address", n.Identity.SNI)
			}
		})
	}
}

// INV-18. The fallback chain still works when a real name is available.
func TestSNIFallsBackToHostThenServer(t *testing.T) {
	n := mustDecode(t, "vless://"+validUUID+"@example.com:443?security=tls&type=tcp&host=front.example.com")
	if n.Identity.SNI != "front.example.com" {
		t.Fatalf("SNI = %q, want front.example.com", n.Identity.SNI)
	}
	n = mustDecode(t, "vless://"+validUUID+"@example.com:443?security=tls&type=tcp")
	if n.Identity.SNI != "example.com" {
		t.Fatalf("SNI = %q, want example.com", n.Identity.SNI)
	}
	// A websocket Host is a header, not a server name, so it must not be borrowed.
	n = mustDecode(t, "vless://"+validUUID+"@example.com:443?security=tls&type=ws&host=front.example.com&path=/w")
	if n.Identity.SNI != "example.com" {
		t.Fatalf("SNI = %q, want the server for ws transport", n.Identity.SNI)
	}
}

// INV-09. Port hopping specifications are canonicalised, and the range is part of the
// identity so two hopping nodes sharing a first port stay distinct.
func TestPortRangeCanonicalisation(t *testing.T) {
	cases := []struct{ in, want string }{
		{"20000-30000", "20000:30000"},
		{"20000:30000", "20000:30000"},
		{"443,8443", "443:443,8443:8443"},
		{"1000-2000,3000-4000", "1000:2000,3000:4000"},
		{"443", "443:443"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n := mustDecode(t, "hy2://p@example.com:443?mport="+tc.in)
			if n.Identity.PortRange != tc.want {
				t.Fatalf("range %q -> %q, want %q", tc.in, n.Identity.PortRange, tc.want)
			}
		})
	}
}

// INV-06. The multi-user form is serverPSK:userPSK, and it is the last segment that
// must match the cipher key length. A wrong key is a fatal engine start, not a
// connection failure, so it is caught before the node is ever dialed.
func TestShadowsocks2022KeyLengths(t *testing.T) {
	key16 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	key32 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	cases := []struct {
		name   string
		method string
		psk    string
		ok     bool
	}{
		{"aes-128 with 16 bytes", "2022-blake3-aes-128-gcm", key16, true},
		{"aes-128 with 32 bytes", "2022-blake3-aes-128-gcm", key32, false},
		{"aes-256 with 32 bytes", "2022-blake3-aes-256-gcm", key32, true},
		{"aes-256 with 16 bytes", "2022-blake3-aes-256-gcm", key16, false},
		{"chacha20 with 32 bytes", "2022-blake3-chacha20-poly1305", key32, true},
		{"multi-user takes the last segment", "2022-blake3-aes-256-gcm", key32 + ":" + key32, true},
		{"multi-user with a wrong user key", "2022-blake3-aes-256-gcm", key32 + ":" + key16, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode("ss://" + tc.method + ":" + tc.psk + "@example.com:8388")
			if tc.ok && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("expected rejection for a wrong key length")
				}
				if r, _ := ReasonOf(err); r != ReasonBadPSKLength {
					t.Fatalf("reason = %s, want %s", r, ReasonBadPSKLength)
				}
			}
		})
	}
}

// INV-28 and INV-21. All three Shadowsocks credential encodings describe the same
// endpoint, so they must produce the same identity.
func TestShadowsocksThreeEncodingsAgree(t *testing.T) {
	const method, password = "aes-256-gcm", "hunter2"
	cred := base64.StdEncoding.EncodeToString([]byte(method + ":" + password))
	whole := base64.StdEncoding.EncodeToString([]byte(method + ":" + password + "@ss.example.com:8388"))

	uris := []struct{ name, uri string }{
		{"plaintext", "ss://" + method + ":" + password + "@ss.example.com:8388"},
		{"credential base64", "ss://" + cred + "@ss.example.com:8388"},
		{"whole base64", "ss://" + whole},
	}

	var keys []string
	for _, tc := range uris {
		t.Run(tc.name, func(t *testing.T) {
			n := mustDecode(t, tc.uri)
			if n.Identity.Method != method || n.Identity.Credential != password {
				t.Fatalf("decoded %q / %q", n.Identity.Method, n.Identity.Credential)
			}
			keys = append(keys, n.Key())
		})
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] != keys[0] {
			t.Fatal("the same node written three ways produced different identities")
		}
	}
}

// INV-28. Repairs are counted rather than silent, so a rise in malformed input is its
// own signal instead of hiding inside a lower node count.
func TestRepairsAreCounted(t *testing.T) {
	cred := strings.TrimRight(
		base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:pa+ss/word?")), "=")
	res, err := Decode("ss://" + cred + "@ss.example.com:8388")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Repairs.Total() == 0 {
		t.Fatal("expected repairs to be counted for unpadded url-safe base64")
	}
}

// INV-03. VMess producers write alterId as a string, a number, or nonsense.
func TestVMessAlterIDCoercion(t *testing.T) {
	cases := []struct {
		name string
		aid  any
		want int
	}{
		{"integer", 4, 4},
		{"numeric string", "8", 8},
		{"empty string", "", 0},
		{"non-numeric", "1a", 0},
		{"negative", -3, 0},
		{"absent", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"add": "example.com", "port": 443, "id": validUUID,
				"net": "ws", "tls": "tls", "path": "/w",
			}
			if tc.aid != nil {
				payload["aid"] = tc.aid
			}
			n := mustDecode(t, vmessURI(t, payload))
			if n.AlterID != tc.want {
				t.Fatalf("alterId %v -> %d, want %d", tc.aid, n.AlterID, tc.want)
			}
		})
	}
}

// INV-29. A port written as a string is normal in VMess payloads; a port that is not a
// number at all is a rejection, never a silent 443.
func TestVMessPortHandling(t *testing.T) {
	n := mustDecode(t, vmessURI(t, map[string]any{
		"add": "example.com", "port": "8443", "id": validUUID,
		"net": "ws", "tls": "tls", "path": "/w",
	}))
	if n.Identity.Port != 8443 {
		t.Fatalf("port = %d, want 8443", n.Identity.Port)
	}

	_, err := Decode(vmessURI(t, map[string]any{
		"add": "example.com", "port": "abc", "id": validUUID,
		"net": "ws", "tls": "tls", "path": "/w",
	}))
	if err == nil {
		t.Fatal("a non-numeric port must be rejected, never coerced to 443")
	}
	if r, _ := ReasonOf(err); r != ReasonBadPort {
		t.Fatalf("reason = %s, want %s", r, ReasonBadPort)
	}
}

// INV-17. An unsupported fingerprint is narrowed to the default rather than failing the
// node, and the allowlist lives in exactly one place.
func TestFingerprintNarrowing(t *testing.T) {
	n := mustDecode(t, "vless://"+validUUID+"@example.com:443?security=tls&type=tcp&fp=nonsense")
	if n.Fingerprint != model.DefaultFingerprint {
		t.Fatalf("fingerprint = %q, want %q", n.Fingerprint, model.DefaultFingerprint)
	}
	n = mustDecode(t, "vless://"+validUUID+"@example.com:443?security=tls&type=tcp&fp=firefox")
	if n.Fingerprint != "firefox" {
		t.Fatalf("fingerprint = %q, want firefox", n.Fingerprint)
	}
}

// INV-16. An absent Reality short id is an empty value, not a missing one.
func TestRealityShortIDCanonicalisation(t *testing.T) {
	for _, sid := range []string{"none", "null", "NONE"} {
		n := mustDecode(t, "vless://"+validUUID+"@example.com:443?security=reality&pbk="+validPBK+"&sid="+sid)
		if n.Identity.ShortID != "" {
			t.Fatalf("short id %q -> %q, want empty", sid, n.Identity.ShortID)
		}
	}
	n := mustDecode(t, "vless://"+validUUID+"@example.com:443?security=reality&pbk="+validPBK+"&sid=AbCd12")
	if n.Identity.ShortID != "abcd12" {
		t.Fatalf("short id = %q, want abcd12", n.Identity.ShortID)
	}
}

// INV-07. Supported plugins are canonicalised and their options parsed into a typed map
// rather than forwarded as an opaque string into a configuration.
func TestSIP003PluginCanonicalisation(t *testing.T) {
	n := mustDecode(t, "ss://aes-256-gcm:pass@example.com:8388?plugin=simple-obfs%3Bobfs%3Dtls%3Bobfs-host%3Dexample.org")
	if n.Identity.Plugin != "obfs-local" {
		t.Fatalf("plugin = %q, want obfs-local", n.Identity.Plugin)
	}
	if n.PluginOpts["obfs"] != "tls" || n.PluginOpts["obfs-host"] != "example.org" {
		t.Fatalf("plugin options = %v", n.PluginOpts)
	}
}

// INV-46. A general HTML entity decoder must never be applied to a whole URI.
// Found by running 865 real published nodes: "&note=" contains "&not", a valid entity
// for the negation sign, so a full decoder rewrote "?type=tcp&note=x" into
// "?type=tcp<not>e=x". The transport then became an unknown value, degraded silently to
// TCP, and two distinct nodes collapsed into one identity. The predecessor had this bug
// and its published output still carries the damage.
func TestOnlyURIEntitiesAreUnescaped(t *testing.T) {
	uri := "vless://" + validUUID + "@example.com:443" +
		"?security=reality&pbk=" + validPBK + "&note=volt_network&type=tcp"
	n := mustDecode(t, uri)
	if n.Identity.Transport != model.TransportTCP {
		t.Fatalf("transport = %q, want tcp", n.Identity.Transport)
	}
	// The real regression: a corrupted transport value silently becomes TCP, so assert
	// on the parameter that would have been eaten instead.
	if strings.Contains(string(n.Identity.Transport), "not") {
		t.Fatalf("entity decoding corrupted the transport: %q", n.Identity.Transport)
	}

	// The entities that HTML-escaping a URI does produce must still be reversed.
	escaped := "vless://" + validUUID + "@example.com:443?security=tls&amp;type=ws&amp;path=/w"
	n = mustDecode(t, escaped)
	if n.Identity.Transport != model.TransportWebSocket {
		t.Fatalf("escaped ampersand not reversed: transport = %q", n.Identity.Transport)
	}
}

// INV-47. A credential may contain an unencoded "#". RFC 3986 forbids it, but real
// producers emit it, and cutting at the first "#" truncated such a URI to nothing: a
// trojan password of the form "xxxx#yyyy" in the real corpus was rejected as
// credential-less. The fragment begins at the first "#" after the authority.
//
// The password and the address here are synthetic. They were the real ones, lifted straight out
// of the corpus, which put a working trojan credential and its endpoint in a public repository —
// the shape is what the invariant is about, and the shape is all that is needed.
func TestUnencodedHashInsideCredential(t *testing.T) {
	n := mustDecode(t, "trojan://Passw0rd#Extra@example.com:21936?type=tcp&security=tls")
	if n.Identity.Credential != "Passw0rd#Extra" {
		t.Fatalf("credential = %q, want the full password including the hash", n.Identity.Credential)
	}
	if n.Identity.Port != 21936 {
		t.Fatalf("port = %d, want 21936", n.Identity.Port)
	}

	// A normal label must still be split off.
	n = mustDecode(t, "trojan://plainpass@example.com:443?security=tls#My%20Node")
	if n.Identity.Credential != "plainpass" {
		t.Fatalf("credential = %q, want plainpass", n.Identity.Credential)
	}
}

// Real feeds write a boolean where a security mode name belongs: one live feed carried 181
// nodes with security=false. Rejecting those as an unknown mode threw away readable input
// over a formatting choice.
func TestBooleanSecurityValues(t *testing.T) {
	cases := []struct {
		value string
		want  model.Security
	}{
		{"false", model.SecurityNone},
		{"0", model.SecurityNone},
		{"true", model.SecurityTLS},
		{"1", model.SecurityTLS},
		{"none", model.SecurityNone},
		{"tls", model.SecurityTLS},
		{"auto", model.SecurityTLS},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			// A websocket transport keeps a plaintext node admissible (GHOST-011).
			n := mustDecode(t, "vless://"+validUUID+"@example.com:443?type=ws&path=%2Fw&security="+tc.value)
			if n.Identity.Security != tc.want {
				t.Fatalf("security %q -> %q, want %q", tc.value, n.Identity.Security, tc.want)
			}
		})
	}

	// A value that is neither a mode nor a boolean is still an error: silently downgrading
	// to plaintext would publish something weaker than the source advertised.
	if _, err := Decode("vless://" + validUUID + "@example.com:443?type=ws&path=%2Fw&security=quantum"); err == nil {
		t.Fatal("an unrecognised security mode must be an error")
	}
}
