package pipeline

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tuftytech/shellshift/internal/intake"
)

// listFetcher trusts the given test servers and nothing else.
func listFetcher(t *testing.T, servers ...*httptest.Server) *intake.Fetcher {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	f := intake.NewFetcher(intake.DefaultLimits())
	cfg := servers[0].Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.RootCAs = pool
	f.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	return f
}

// A whitelist cut at the line cap says so, in both feeds.
//
// The reader has recorded the cut since it was written and this loader did not look. On a live run
// the CIDR feed came back with exactly 50 000 lines — the cap, to the line — and the report said
// only how many entries had loaded, which is the number that looks fine. A short whitelist
// under-classifies silently, and the class it empties is the one claim this project is making, so
// the failure arrives looking like a catalogue nobody qualified for.
func TestATruncatedWhitelistIsReportedAsAProblem(t *testing.T) {
	domains := feedServer(t, "a.example.com", "b.example.com", "c.example.com", "d.example.com")
	defer domains.Close()
	networks := feedServer(t, "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
	defer networks.Close()

	f := listFetcher(t, domains, networks)
	f.Limits.MaxNodesPerSource = 2

	wl, problems := LoadWhitelist(context.Background(), f,
		[]string{domains.URL}, []string{networks.URL})

	if len(problems) != 2 {
		t.Fatalf("problems = %v, want one per cut feed", problems)
	}
	for _, want := range []string{domains.URL, networks.URL} {
		found := false
		for _, p := range problems {
			if strings.Contains(p, want) && strings.Contains(p, "2-line cap") {
				found = true
			}
		}
		if !found {
			t.Errorf("no problem names %s and the cap it hit: %v", want, problems)
		}
	}

	// A partial load is still useful — losing the network feed must not cost the domain
	// matches (INV-32) — so the entries that did arrive are still in the list.
	if !wl.Loaded() {
		t.Fatal("a truncated feed still loaded entries; the list must not be empty")
	}
	if !wl.Match("a.example.com") {
		t.Error("the entries that were read must still match")
	}
}

// A feed that ends exactly at the cap is reported too, and that is deliberate.
//
// From the outside there is no way to tell a list of exactly 50 000 entries from the first 50 000
// of a longer one: the body ended because the reader stopped. Treating that as complete is
// precisely how the live failure stayed invisible, so the conservative reading is the one that
// gets reported.
func TestAWhitelistEndingExactlyAtTheCapIsStillReported(t *testing.T) {
	domains := feedServer(t, "a.example.com", "b.example.com")
	defer domains.Close()

	f := listFetcher(t, domains)
	f.Limits.MaxNodesPerSource = 2

	if _, problems := LoadWhitelist(context.Background(), f, []string{domains.URL}, nil); len(problems) != 1 {
		t.Fatalf("problems = %v, want the cut reported at exactly the cap", problems)
	}

	// And a feed that fits reports nothing: a warning on every run is a warning nobody reads.
	f.Limits.MaxNodesPerSource = 50
	wl, problems := LoadWhitelist(context.Background(), f, []string{domains.URL}, nil)
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	if !wl.Match("b.example.com") {
		t.Error("the whole list must be loaded when it fits")
	}
}
