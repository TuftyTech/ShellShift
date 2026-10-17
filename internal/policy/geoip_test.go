package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// geoServer answers with a code only. Tests that care about the readable fields use
// geoPlaceServer.
func geoServer(t *testing.T, answers map[string]string, calls *atomic.Int64) *httptest.Server {
	t.Helper()
	places := make(map[string]Place, len(answers))
	for q, cc := range answers {
		places[q] = Place{CC: cc}
	}
	return geoPlaceServer(t, places, calls)
}

func geoPlaceServer(t *testing.T, answers map[string]Place, calls *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		var queries []string
		if err := json.NewDecoder(r.Body).Decode(&queries); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		type row struct {
			Query       string `json:"query"`
			Status      string `json:"status"`
			CountryCode string `json:"countryCode"`
			Country     string `json:"country"`
			City        string `json:"city"`
			Timezone    string `json:"timezone"`
			AS          string `json:"as"`
			ASName      string `json:"asname"`
			ISP         string `json:"isp"`
			Org         string `json:"org"`
			Reverse     string `json:"reverse"`
		}
		out := make([]row, 0, len(queries))
		for _, q := range queries {
			if p, ok := answers[q]; ok {
				out = append(out, row{Query: q, Status: "success",
					CountryCode: p.CC, Country: p.Country, City: p.City,
					Timezone: p.Timezone, AS: p.ASN, ASName: p.ASName,
					ISP: p.ISP, Org: p.Org, Reverse: p.Reverse})
				continue
			}
			out = append(out, row{Query: q, Status: "fail"})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func locator(t *testing.T, srv *httptest.Server) *GeoLocator {
	t.Helper()
	g := NewGeoLocator()
	g.Endpoint = srv.URL
	g.Pacing = 0
	g.Client = srv.Client()
	return g
}

func TestGeoLookupFillsCountries(t *testing.T) {
	srv := geoServer(t, map[string]string{"93.184.216.34": "US", "1.1.1.1": "AU"}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(), []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("1.1.1.1"),
	})
	if got["93.184.216.34"].CC != "US" || got["1.1.1.1"].CC != "AU" {
		t.Fatalf("got %v", got)
	}
}

// The readable place is what makes two nodes in one country distinguishable in a client, so it is
// carried through rather than reduced to a code.
func TestGeoLookupCarriesCountryNameAndCity(t *testing.T) {
	srv := geoPlaceServer(t, map[string]Place{
		"203.0.113.7": {CC: "JP", Country: "Japan", City: "Tokyo"},
	}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(),
		[]netip.Addr{netip.MustParseAddr("203.0.113.7")})
	p := got["203.0.113.7"]
	if p.CC != "JP" || p.Country != "Japan" || p.City != "Tokyo" {
		t.Fatalf("got %+v, want JP/Japan/Tokyo", p)
	}
}

// The readable fields come from a third party over plaintext and end up in a file a client
// parses, so they are treated as hostile input. A name carrying a newline would split one
// subscription entry into two.
func TestPlaceNamesAreSanitised(t *testing.T) {
	long := strings.Repeat("Ы", 200)
	srv := geoPlaceServer(t, map[string]Place{
		"1.1.1.1": {CC: "AU", Country: "Aus\ntralia", City: "Syd\r\nney"},
		"8.8.8.8": {CC: "US", Country: "United · States", City: "Ash#burn"},
		"9.9.9.9": {CC: "DE", Country: long, City: "  Berlin  "},
	}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(), []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("9.9.9.9"),
	})

	for addr, p := range got {
		for _, forbidden := range []string{"\n", "\r", "·", "#"} {
			if strings.Contains(p.Country, forbidden) || strings.Contains(p.City, forbidden) {
				t.Fatalf("%s: %q / %q still contains %q", addr, p.Country, p.City, forbidden)
			}
		}
	}
	// Bounded by runes, so a Cyrillic name is not cut mid-character.
	de := got["9.9.9.9"]
	if r := []rune(de.Country); len(r) > 48 {
		t.Fatalf("name is %d runes, want at most 48", len(r))
	}
	if !utf8.ValidString(de.Country) {
		t.Fatalf("truncation produced invalid UTF-8: %q", de.Country)
	}
	if de.City != "Berlin" {
		t.Fatalf("city = %q, want it trimmed to Berlin", de.City)
	}
	// The code itself is unaffected: it is validated separately.
	if got["1.1.1.1"].CC != "AU" {
		t.Fatalf("a sanitised name must not lose the code, got %+v", got["1.1.1.1"])
	}
}

// An unknown country is absent, never a placeholder. The predecessor wrote the string "UN" and
// then filtered it out downstream, which made "unknown" and a country called UN the same value.
func TestUnknownCountryIsAbsent(t *testing.T) {
	srv := geoServer(t, map[string]string{}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(),
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")})
	if _, present := got["203.0.113.1"]; present {
		t.Fatalf("an unknown country must be absent, got %v", got)
	}
}

// Addresses in the same /24 cost one lookup between them. That single choice removes most of
// the requests: nodes cluster behind providers.
func TestNeighboursShareOneLookup(t *testing.T) {
	var calls atomic.Int64
	srv := geoServer(t, map[string]string{
		"93.184.216.1": "US", "93.184.216.34": "US", "93.184.216.200": "US",
	}, &calls)
	defer srv.Close()

	g := locator(t, srv)
	got := g.Lookup(context.Background(), []netip.Addr{
		netip.MustParseAddr("93.184.216.1"),
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("93.184.216.200"),
	})
	if len(got) != 3 {
		t.Fatalf("all three addresses should get a country, got %v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("made %d requests, want 1 for three addresses in one network", calls.Load())
	}
}

// A second call costs nothing, including for addresses whose country is unknown: asking again
// for every node that shares a gap is how one gap becomes a measurable share of the work.
func TestNegativeAnswersAreCachedToo(t *testing.T) {
	var calls atomic.Int64
	srv := geoServer(t, map[string]string{}, &calls)
	defer srv.Close()

	g := locator(t, srv)
	addrs := []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	g.Lookup(context.Background(), addrs)
	g.Lookup(context.Background(), addrs)
	g.Lookup(context.Background(), addrs)

	if calls.Load() != 1 {
		t.Fatalf("made %d requests, want 1: a negative answer must be cached", calls.Load())
	}
}

// A rate limit or an outage is not worth failing a run over: the country is decoration.
func TestServiceFailureIsNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(),
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")})
	if len(got) != 0 {
		t.Fatalf("a failed lookup must yield nothing rather than a guess, got %v", got)
	}
}

// A value that is not a country code is not turned into one.
func TestMalformedCodesAreRejected(t *testing.T) {
	srv := geoServer(t, map[string]string{
		"1.1.1.1": "USA", "8.8.8.8": "1A", "9.9.9.9": "",
	}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(), []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("9.9.9.9"),
	})
	if len(got) != 0 {
		t.Fatalf("malformed codes must be rejected, got %v", got)
	}
}

// The same request answers more than the country, and the extra answers are kept.
//
// The batch call is made once per distinct address whatever it asks for, so the network cost of
// ASN, ISP, network owner, reverse name and timezone is zero — the fields simply have to be named
// in the query. Without them the node card could say where a node is and nothing about whose
// machine it is, which is the difference between "NL" and "a Hetzner box in Amsterdam whose PTR is
// a hosting template".
func TestTheBatchAnswerCarriesTheNetworkOwner(t *testing.T) {
	want := Place{
		CC: "DE", Country: "Germany", City: "Nuremberg", Timezone: "Europe/Berlin",
		ASN: "AS24940 Hetzner Online GmbH", ASName: "HETZNER-AS",
		ISP: "Hetzner Online GmbH", Org: "Hetzner Online GmbH",
		Reverse: "static.88-99-1-1.clients.your-server.de",
	}
	srv := geoPlaceServer(t, map[string]Place{"88.99.1.1": want}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(), []netip.Addr{netip.MustParseAddr("88.99.1.1")})
	if got["88.99.1.1"] != want {
		t.Fatalf("place = %+v,\nwant %+v", got["88.99.1.1"], want)
	}

	// The provider only answers what the query names, so the field list is part of the contract.
	for _, field := range []string{"timezone", "as", "asname", "isp", "org", "reverse"} {
		if !strings.Contains(NewGeoLocator().Endpoint, field) {
			t.Errorf("the endpoint's fields= list does not ask for %q", field)
		}
	}
}

// A provider that answers less must leave the fields empty rather than acquire a placeholder.
//
// This is INV-36 at the edge of the system: the predecessor wrote "UN" for an unknown country and
// then filtered it out again downstream. An absent ASN is absent.
func TestMissingEnrichmentStaysAbsent(t *testing.T) {
	srv := geoServer(t, map[string]string{"1.2.3.4": "NL"}, nil)
	defer srv.Close()

	got := locator(t, srv).Lookup(context.Background(), []netip.Addr{netip.MustParseAddr("1.2.3.4")})
	p := got["1.2.3.4"]
	if p.CC != "NL" {
		t.Fatalf("cc = %q, want NL", p.CC)
	}
	if p.ASN != "" || p.ISP != "" || p.Org != "" || p.Reverse != "" || p.Timezone != "" || p.ASName != "" {
		t.Errorf("a country-only answer invented enrichment: %+v", p)
	}
}
