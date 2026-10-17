package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// GeoLocator maps addresses to country codes.
//
// The lookup is by address rather than by hostname, and by /24 network rather than by exact
// address, because that is where the reuse is: many nodes sit behind the same provider, and
// resolving a country per node is work the answer does not depend on.
//
// A missing answer is an absent country, never a placeholder. The predecessor wrote the string
// "UN" and then had to filter it out again downstream, which meant a node whose country was
// unknown and a node in a country literally called UN were the same value.
type GeoLocator struct {
	// Endpoint is a batch lookup service. It is plain HTTP on the provider the predecessor
	// used, which is why the country is treated as decoration and never as a security input.
	Endpoint string
	// BatchSize is how many addresses go in one request.
	BatchSize int
	// Pacing is the delay between batches, to stay inside a free tier.
	Pacing time.Duration
	Client *http.Client

	mu    sync.Mutex
	cache map[string]Place
}

// Place is what is known about where an address is.
//
// The readable name is carried rather than derived from the code, because deriving it means a
// table of some 250 entries and the provider answers with it already. Any field may be absent,
// and absent is absent: the label is built to read correctly without it.
type Place struct {
	// CC is the two-letter code, always either two letters or empty.
	CC string
	// Country is the readable name, e.g. "Japan".
	Country string
	// City is the city, e.g. "Tokyo".
	City string
	// Timezone is the IANA name, e.g. "Europe/Berlin".
	Timezone string
	// ASN, ASName, ISP and Org describe whose network the address belongs to, and Reverse is
	// its PTR name.
	//
	// They cost nothing: the batch call is made once per distinct address whatever it asks for,
	// so the only thing standing between the run and this data was naming the fields in the
	// query. They matter because a country is a poor answer to "what am I connecting to" — the
	// difference between "NL" and "a Hetzner machine whose PTR is a hosting template" is the
	// difference between decoration and a fact a reader can act on.
	//
	// ASN arrives as one string, "AS24940 Hetzner Online GmbH", and is kept verbatim: splitting
	// a provider's field into number and name is how a placeholder gets invented for the half
	// that turns out to be missing.
	ASN     string
	ASName  string
	ISP     string
	Org     string
	Reverse string
}

// NewGeoLocator returns a locator with conservative pacing.
func NewGeoLocator() *GeoLocator {
	return &GeoLocator{
		// The field list is the whole contract with the provider: it answers what is named and
		// nothing else, and every name here rides on the request the country already required.
		Endpoint: "http://ip-api.com/batch?fields=query,status,countryCode,country,city," +
			"timezone,as,asname,isp,org,reverse",
		BatchSize: 100,
		Pacing:    4500 * time.Millisecond,
		Client:    &http.Client{Timeout: 15 * time.Second},
		cache:     map[string]Place{},
	}
}

// cacheKey groups an address with its neighbours.
//
// A /24 for IPv4 and the exact address for IPv6: hosts in the same /24 are in the same place
// often enough for a country code, and that single choice removes most of the lookups.
func cacheKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
	}
	return addr.String()
}

// Lookup fills in places for the given addresses, returning a map keyed by the address string.
// Addresses whose place is unknown are simply absent from the result.
func (g *GeoLocator) Lookup(ctx context.Context, addrs []netip.Addr) map[string]Place {
	out := map[string]Place{}
	pending := make([]netip.Addr, 0, len(addrs))

	g.mu.Lock()
	for _, a := range addrs {
		if p, ok := g.cache[cacheKey(a)]; ok {
			if p.CC != "" {
				out[a.String()] = p
			}
			continue
		}
		pending = append(pending, a)
	}
	g.mu.Unlock()

	// Deduplicate by network so one request covers many nodes.
	byKey := map[string]netip.Addr{}
	for _, a := range pending {
		byKey[cacheKey(a)] = a
	}
	unique := make([]netip.Addr, 0, len(byKey))
	for _, a := range byKey {
		unique = append(unique, a)
	}

	for start := 0; start < len(unique); start += g.BatchSize {
		if ctx.Err() != nil {
			break
		}
		end := start + g.BatchSize
		if end > len(unique) {
			end = len(unique)
		}
		found := g.batch(ctx, unique[start:end])

		g.mu.Lock()
		for _, a := range unique[start:end] {
			// A negative answer is cached too: an address with no country will not acquire
			// one during this run, and asking again for every node that shares its network is
			// how one gap becomes a measurable share of the work.
			g.cache[cacheKey(a)] = found[a.String()]
		}
		g.mu.Unlock()

		if end < len(unique) && g.Pacing > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(g.Pacing):
			}
		}
	}

	// Answer every requested address from the cache, including the ones covered by a
	// neighbour lookup.
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range addrs {
		if p := g.cache[cacheKey(a)]; p.CC != "" {
			out[a.String()] = p
		}
	}
	return out
}

func (g *GeoLocator) batch(ctx context.Context, addrs []netip.Addr) map[string]Place {
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

	queries := make([]string, 0, len(addrs))
	for _, a := range addrs {
		queries = append(queries, a.String())
	}
	body, err := json.Marshal(queries)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.Endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A rate limit is not an error worth failing a run over: the country is decoration.
		return nil
	}

	var rows []row
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil
	}

	out := make(map[string]Place, len(rows))
	for _, r := range rows {
		if r.Status != "success" {
			continue
		}
		cc := strings.ToUpper(strings.TrimSpace(r.CountryCode))
		// Two alphabetic characters or nothing. A value that is not a country code is not
		// turned into a placeholder.
		if len(cc) != 2 || !isAlpha(cc) {
			continue
		}
		// The readable fields are bounded and stripped of anything that would break a label. They
		// come from a third party over plaintext and end up in a file a client parses, so they are
		// treated as hostile input rather than as data: a name carrying a newline would split one
		// subscription entry into two.
		// Every readable field goes through the same sanitiser as the country name, for the same
		// reason: these arrive from a third party over plaintext and end up in a file a client
		// parses, so a value carrying a newline would split one subscription entry into two.
		out[r.Query] = Place{
			CC:       cc,
			Country:  sanitisePlace(r.Country),
			City:     sanitisePlace(r.City),
			Timezone: sanitisePlace(r.Timezone),
			ASN:      sanitisePlace(r.AS),
			ASName:   sanitisePlace(r.ASName),
			ISP:      sanitisePlace(r.ISP),
			Org:      sanitisePlace(r.Org),
			Reverse:  sanitisePlace(r.Reverse),
		}
	}
	return out
}

// sanitisePlace bounds a provider-supplied name and removes what would corrupt a subscription
// line or a rendered page.
func sanitisePlace(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Control characters, line breaks and the separator the label itself uses.
	s = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f:
			return -1
		case r == '·': // the label separator
			return -1
		case r == '#': // would start a fragment in a published URI
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)

	// A place name longer than this is not a place name. The bound is on runes rather than bytes
	// so a Cyrillic or CJK name is not cut mid-character.
	const maxRunes = 48
	if r := []rune(s); len(r) > maxRunes {
		s = strings.TrimSpace(string(r[:maxRunes]))
	}
	return s
}

func isAlpha(s string) bool {
	for _, c := range s {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}
