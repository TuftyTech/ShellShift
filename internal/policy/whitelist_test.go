package policy

import (
	"strings"
	"testing"
)

func loaded(t *testing.T, domains, cidrs string) *Whitelist {
	t.Helper()
	w := NewWhitelist()
	if _, err := w.AddDomains(strings.NewReader(domains)); err != nil {
		t.Fatalf("domains: %v", err)
	}
	if _, err := w.AddNetworks(strings.NewReader(cidrs)); err != nil {
		t.Fatalf("cidrs: %v", err)
	}
	return w
}

// The suffix walk never tests the bare public suffix. Without that, an entry for one domain
// whitelists every domain sharing its ending — and for a two-label entry only an exact match
// counts (INV-32).
func TestSuffixWalkNeverReachesTheBareSuffix(t *testing.T) {
	w := loaded(t, "example.com\ncdn.provider.net\n", "")

	match := []string{"example.com", "www.example.com", "a.b.example.com",
		"cdn.provider.net", "edge.cdn.provider.net"}
	for _, host := range match {
		if !w.Match(host) {
			t.Errorf("%s should match", host)
		}
	}

	miss := []string{"com", "notexample.com", "example.com.evil.org",
		"provider.net", "net", "example.org"}
	for _, host := range miss {
		if w.Match(host) {
			t.Errorf("%s must NOT match", host)
		}
	}
}

// One zero-length prefix in a third-party feed is all it takes to whitelist the internet.
func TestZeroLengthPrefixIsDiscarded(t *testing.T) {
	w := loaded(t, "", "0.0.0.0/0\n::/0\n203.0.113.0/24\n")
	if w.Match("8.8.8.8") {
		t.Fatal("a zero-length prefix must not whitelist everything")
	}
	if !w.Match("203.0.113.7") {
		t.Fatal("a real prefix must still match")
	}
}

func TestCIDRContainmentAndFamilies(t *testing.T) {
	w := loaded(t, "", "10.20.0.0/16\n2001:4860:4860::/48\n")
	if !w.Match("10.20.30.40") {
		t.Error("address inside the prefix should match")
	}
	if w.Match("10.21.30.40") {
		t.Error("address outside the prefix must not match")
	}
	if !w.Match("2001:4860:4860::8888") {
		t.Error("ipv6 inside the prefix should match")
	}
	// A v4 address must not be tested against a v6 prefix or the other way round.
	if w.Match("2001:4860:4861::1") {
		t.Error("ipv6 outside the prefix must not match")
	}
}

// Feeds carry comments and mixed case, and a bare address inside a domain feed.
func TestFeedParsingTolerance(t *testing.T) {
	w := loaded(t, "# a comment\n  EXAMPLE.COM  \n\n1.2.3.4\n", "  # note\n  10.0.0.0/8  \n")
	if !w.Match("example.com") {
		t.Error("case and whitespace must be normalised")
	}
	if !w.Match("1.2.3.4") {
		t.Error("a bare address in a domain feed must be usable")
	}
	if !w.Match("10.1.2.3") {
		t.Error("a commented cidr feed must still load")
	}
}

// An empty whitelist classifies nothing. The safe direction is that an outage cannot promote
// nodes into the class, and cannot silently demote the catalogue without saying so either.
func TestEmptyWhitelistMatchesNothing(t *testing.T) {
	w := NewWhitelist()
	if w.Loaded() {
		t.Fatal("an empty whitelist must not report itself as loaded")
	}
	for _, host := range []string{"example.com", "1.2.3.4"} {
		if w.Match(host) {
			t.Fatalf("%s matched an empty whitelist", host)
		}
	}
}

func TestBracketedAndListedServerNames(t *testing.T) {
	w := loaded(t, "example.com\n", "2001:db9::/32\n")
	if !w.Match("example.com, other.org") {
		t.Error("a comma-separated value must use its first entry")
	}
	if !w.Match("[2001:db9::1]") {
		t.Error("a bracketed ipv6 literal must be unwrapped")
	}
}
