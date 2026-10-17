package policy

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// Whitelist holds the censor whitelist: the domains and networks a filtering regime lets
// through even when it blocks everything else.
//
// The matching semantics are carried over exactly, because each detail is load-bearing and
// two of them are counter-intuitive (INV-32):
//
//   - The suffix walk never tests the bare public suffix, so an entry for "example.com" does
//     not whitelist "anything.com". For a two-label domain the walk is empty and only an
//     exact match counts.
//   - A network with a zero-length prefix is discarded at load. Without that, a single
//     "0.0.0.0/0" line in a third-party feed whitelists the entire internet.
type Whitelist struct {
	domains  map[string]bool
	literals map[string]bool
	networks []netip.Prefix
}

// NewWhitelist returns an empty whitelist. An empty whitelist classifies nothing, which is
// the safe direction: the predecessor also warned rather than failing when its feeds were
// unavailable, and that instinct was right.
func NewWhitelist() *Whitelist {
	return &Whitelist{domains: map[string]bool{}, literals: map[string]bool{}}
}

// Loaded reports whether anything was loaded. A caller must check this before trusting a
// negative classification, or an outage silently reclassifies the whole catalogue.
func (w *Whitelist) Loaded() bool {
	return len(w.domains) > 0 || len(w.literals) > 0 || len(w.networks) > 0
}

// Counts returns how much was loaded, for the run report.
func (w *Whitelist) Counts() (domains, literals, networks int) {
	return len(w.domains), len(w.literals), len(w.networks)
}

// AddDomains parses a domain feed.
func (w *Whitelist) AddDomains(r io.Reader) (int, error) {
	added := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		line := cleanFeedLine(sc.Text())
		if line == "" {
			continue
		}
		if _, err := netip.ParseAddr(line); err == nil {
			// A bare address in a domain feed is compared as a literal, which is what the
			// predecessor did and what the feeds actually contain.
			w.literals[line] = true
			added++
			continue
		}
		w.domains[line] = true
		added++
	}
	return added, sc.Err()
}

// AddNetworks parses a CIDR feed.
func (w *Whitelist) AddNetworks(r io.Reader) (int, error) {
	added := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		line := cleanFeedLine(sc.Text())
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			if addr, aerr := netip.ParseAddr(line); aerr == nil {
				w.literals[addr.String()] = true
				added++
			}
			continue
		}
		// A zero-length prefix would whitelist everything. One such line in a third-party
		// feed is all it takes, so it is dropped at load rather than trusted.
		if prefix.Bits() == 0 {
			continue
		}
		w.networks = append(w.networks, prefix.Masked())
		added++
	}
	return added, sc.Err()
}

// Match reports whether a target is whitelisted.
func (w *Whitelist) Match(target string) bool {
	t := strings.TrimSpace(strings.ToLower(target))
	t = strings.Split(t, ",")[0]
	t = strings.Trim(t, "[] \t")
	if t == "" || !w.Loaded() {
		return false
	}

	if w.domains[t] || w.literals[t] {
		return true
	}

	if addr, err := netip.ParseAddr(t); err == nil {
		addr = addr.Unmap()
		for _, n := range w.networks {
			if n.Addr().Is4() != addr.Is4() {
				continue
			}
			if n.Contains(addr) {
				return true
			}
		}
		return false
	}

	// The suffix walk. Starting at 1 skips the exact match already tested, and stopping
	// before the last label is what prevents an entry for "example.com" from whitelisting
	// every ".com" domain.
	parts := strings.Split(t, ".")
	for i := 1; i < len(parts)-1; i++ {
		if w.domains[strings.Join(parts[i:], ".")] {
			return true
		}
	}
	return false
}

// cleanFeedLine strips comments and whitespace from a feed line.
func cleanFeedLine(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	return strings.ToLower(strings.TrimSpace(line))
}
