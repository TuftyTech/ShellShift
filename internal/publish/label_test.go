package publish

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/model"
)

func TestLabelFormat(t *testing.T) {
	cases := []struct {
		name string
		node model.Node
		code string
		want string
	}{
		{
			"everything known",
			model.Node{Country: "JP", CountryName: "Japan", City: "Tokyo"},
			"3f2a1b0c",
			"🇯🇵 Japan · Tokyo · 3f2a1b0c",
		},
		{
			"city equal to the country is not repeated",
			model.Node{Country: "SG", CountryName: "Singapore", City: "Singapore"},
			"aa11bb22",
			"🇸🇬 Singapore · aa11bb22",
		},
		{
			"country known, city not",
			model.Node{Country: "DE", CountryName: "Germany"},
			"5c9d2e11",
			"🇩🇪 Germany · 5c9d2e11",
		},
		{
			"code only",
			model.Node{Country: "NL"},
			"88b41f02",
			"🇳🇱 NL · 88b41f02",
		},
		{
			// An absent country produces no flag and no name rather than a placeholder. The
			// predecessor wrote "UN" here and filtered it out again downstream.
			"nothing known but the code",
			model.Node{},
			"c0ffee11",
			"c0ffee11",
		},
		{
			"a city without a country still names the place",
			model.Node{City: "Frankfurt"},
			"d00d1234",
			"Frankfurt · d00d1234",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Label(tc.node, tc.code); got != tc.want {
				t.Fatalf("Label = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFlagFromCountryCode(t *testing.T) {
	for cc, want := range map[string]string{
		"JP": "🇯🇵", "RU": "🇷🇺", "US": "🇺🇸", "jp": "🇯🇵",
	} {
		if got := Flag(cc); got != want {
			t.Fatalf("Flag(%q) = %q, want %q", cc, got, want)
		}
	}
	// A code this does not recognise produces nothing rather than a wrong flag.
	for _, bad := range []string{"", "U", "USA", "1A", "??", "U8"} {
		if got := Flag(bad); got != "" {
			t.Fatalf("Flag(%q) = %q, want empty", bad, got)
		}
	}
}

// A label must not be able to change the node it names. The flag is multi-byte UTF-8 and the
// label goes into the URI fragment, so this is the point at which a percent-encoding mistake would
// turn a working node into a broken one — the failure mode the whole project exists to avoid.
func TestLabelDoesNotAlterTheNode(t *testing.T) {
	uris := []string{
		"vless://" + uuid + "@example.com:443?type=tcp&security=reality&pbk=" + pbk + "&sid=6ba8",
		"vless://" + uuid + "@example.com:443?type=ws&security=tls&host=f.example.com&path=%2Fws",
		"trojan://p4ss@example.com:443?security=tls&sni=example.com",
		"ss://aes-256-gcm:hunter2@example.com:8388",
		"hy2://p4ss@example.com:443?sni=example.com",
	}
	labels := []string{
		"🇯🇵 Japan · Tokyo · 3f2a1b0c",
		"🇷🇺 Russia · St Petersburg · a71e0044",
		"🇸🇬 Singapore · aa11bb22",
		"c0ffee11",
	}

	for _, uri := range uris {
		original, err := decode.Decode(uri)
		if err != nil {
			t.Fatalf("decode %.50q: %v", uri, err)
		}
		for _, label := range labels {
			published, err := Encode(original.Node, label)
			if err != nil {
				t.Fatalf("encode with label %q: %v", label, err)
			}
			// The line must survive being written to and read from a subscription file.
			if strings.ContainsAny(published, "\n\r") {
				t.Fatalf("published URI contains a line break: %q", published)
			}
			back, err := decode.Decode(published)
			if err != nil {
				t.Fatalf("republished URI does not decode, label %q: %v\n  %s", label, err, published)
			}
			if back.Node.Key() != original.Node.Key() {
				t.Fatalf("label %q changed the identity:\n  before %s\n  after  %s\n  %s",
					label, original.Node.Key(), back.Node.Key(), published)
			}
		}
	}
}

// The label ends up in a text file a client parses line by line, so it must not be able to carry
// a line break or a fragment delimiter no matter what the geo provider said.
func TestLabelCannotBreakASubscriptionLine(t *testing.T) {
	n := model.Node{Country: "XX", CountryName: "Ab\nnormal", City: "We\r\nird#frag"}
	got := Label(n, "deadbeef")
	for _, forbidden := range []string{"\n", "\r"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("label %q contains %q", got, forbidden)
		}
	}
	if !utf8.ValidString(got) {
		t.Fatalf("label is not valid UTF-8: %q", got)
	}
}

// The short code must be unique across the published set, because a client that keys profiles by
// name silently keeps one of two entries that share one. Eight hex characters is 32 bits: at a
// hundred thousand nodes the chance of at least one collision is about 68 percent, so the length
// is measured against the actual set rather than assumed.
func TestShortCodesAreUniqueAcrossTheSet(t *testing.T) {
	for _, n := range []int{10, 1000, 100_000} {
		t.Run(fmt.Sprintf("%d nodes", n), func(t *testing.T) {
			entries := syntheticEntries(n)
			codes := ShortCodes(entries)

			if len(codes) != n {
				t.Fatalf("assigned %d codes for %d nodes", len(codes), n)
			}
			seen := make(map[string]string, n)
			length := -1
			for key, code := range codes {
				if prev, dup := seen[code]; dup {
					t.Fatalf("code %q assigned to both %s and %s", code, prev, key)
				}
				seen[code] = key
				if length == -1 {
					length = len(code)
				} else if len(code) != length {
					// One length for the whole set: codes of differing lengths in one list read
					// as a defect.
					t.Fatalf("code lengths differ: %d and %d", length, len(code))
				}
				if !strings.HasPrefix(key, code) {
					t.Fatalf("code %q is not a prefix of identity %q", code, key)
				}
			}
			if length < 8 {
				t.Fatalf("code length %d is below the readable minimum of 8", length)
			}
		})
	}
}

// A collision must lengthen the code rather than produce two identical labels. Identities are
// hashes, so a colliding pair cannot be obtained by choosing nodes — it is constructed here and
// asserted against the helper that decides the length.
func TestShortCodesLengthenOnCollision(t *testing.T) {
	a := strings.Repeat("ab", 4) + strings.Repeat("0", 48) // same first 8, differ at 9
	b := strings.Repeat("ab", 4) + strings.Repeat("1", 48)

	codes := shortCodesFor([]string{a, b})
	if codes[a] == codes[b] {
		t.Fatalf("two identities sharing eight characters got the same code %q", codes[a])
	}
	if len(codes[a]) <= 8 {
		t.Fatalf("code length is %d: it must grow past the colliding prefix", len(codes[a]))
	}
	// It grows only as far as needed: these differ at the ninth character.
	if len(codes[a]) != 9 {
		t.Fatalf("code length is %d, want 9: it must grow only as far as the set requires",
			len(codes[a]))
	}
}

// syntheticEntries builds n entries with distinct identities.
func syntheticEntries(n int) []Entry {
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		res := model.Node{Identity: model.Identity{
			Protocol:   model.ProtoVLESS,
			Server:     fmt.Sprintf("h%d.example.com", i),
			Port:       443,
			Credential: uuid,
			Transport:  model.TransportTCP,
			Security:   model.SecurityTLS,
		}}
		out = append(out, Entry{Node: res})
	}
	return out
}
