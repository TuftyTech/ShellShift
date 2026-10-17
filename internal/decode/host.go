package decode

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// hostPattern matches a dotted domain of at least two labels ending in an alphabetic
// TLD. It is deliberately anchored and bounded: each label is 1..63 characters and the
// outer repetition is terminated by a literal dot, so matching is linear and cannot
// backtrack catastrophically.
var hostPattern = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// reservedNames are hostnames that can never denote a usable public endpoint.
var reservedNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
}

// validateHost checks that a host string could denote a public endpoint.
//
// Scope matters here. This is a *syntactic* gate that runs on the literal text the
// source wrote: it rejects loopback and obviously non-routable literals, and shapes
// that are not hostnames at all. It is NOT the egress guard. The real defence resolves
// the name and vets the resulting address immediately before dialing, because a name
// that looks public here can resolve to an internal address later — the predecessor
// checked once and let sing-box resolve again, leaving a rebinding window (INV-33).
// That check lives in internal/policy and applies to every protocol.
func validateHost(host string) error {
	h := strings.TrimSpace(host)
	h = strings.Trim(h, "[]")
	if h == "" {
		return reject(ReasonBadHost, "empty host")
	}
	lower := strings.ToLower(h)

	if reservedNames[lower] {
		return reject(ReasonBadHost, "reserved name %q", h)
	}
	if strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".home.arpa") {
		return reject(ReasonBadHost, "non-public suffix in %q", h)
	}

	if addr, err := netip.ParseAddr(lower); err == nil {
		switch {
		case addr.IsLoopback():
			return reject(ReasonBadHost, "loopback address %q", h)
		case addr.IsUnspecified():
			return reject(ReasonBadHost, "unspecified address %q", h)
		case addr.IsPrivate():
			return reject(ReasonBadHost, "private address %q", h)
		case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
			return reject(ReasonBadHost, "link-local address %q", h)
		case addr.IsMulticast():
			return reject(ReasonBadHost, "multicast address %q", h)
		case addr.IsInterfaceLocalMulticast():
			return reject(ReasonBadHost, "interface-local address %q", h)
		}
		return nil
	}

	if len(h) < 4 {
		return reject(ReasonBadHost, "host too short: %q", h)
	}
	if !hostPattern.MatchString(h) {
		return reject(ReasonBadHost, "not a hostname: %q", h)
	}
	return nil
}

// parsePort converts a port string with no fallback.
//
// The predecessor coerced an unparseable port to 443, so a payload carrying
// "port": "abc" silently became a node on 443 that could never work. A node we cannot
// read is a node we reject (INV-29, GHOST-003).
func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, reject(ReasonMissingPort, "no port")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, reject(ReasonBadPort, "port %q is not a number", s)
	}
	if n <= 0 || n > 65535 {
		return 0, reject(ReasonBadPort, "port %d out of range", n)
	}
	return uint16(n), nil
}

// canonicalPortRange normalises a Hysteria2 port-hopping specification.
//
// Links carry "20000-30000" or a comma list; sing-box wants "20000:30000" entries and
// treats the field as conflicting with a single server port, so the caller must clear
// that too. An unparseable range is rejected rather than passed through: the
// predecessor forwarded arbitrary strings straight into the configuration, where a
// malformed value took down the whole batch (INV-09).
func canonicalPortRange(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil
	}
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(fields) == 0 {
		return "", reject(ReasonBadPortRange, "empty range %q", spec)
	}

	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.ReplaceAll(f, "-", ":")
		lo, hi, isRange := strings.Cut(f, ":")
		low, err := parsePort(lo)
		if err != nil {
			return "", reject(ReasonBadPortRange, "bad low port in %q", f)
		}
		if !isRange {
			out = append(out, itoa(int(low))+":"+itoa(int(low)))
			continue
		}
		high, err := parsePort(hi)
		if err != nil {
			return "", reject(ReasonBadPortRange, "bad high port in %q", f)
		}
		if high < low {
			return "", reject(ReasonBadPortRange, "inverted range %q", f)
		}
		out = append(out, itoa(int(low))+":"+itoa(int(high)))
	}
	return strings.Join(out, ","), nil
}

func itoa(n int) string { return strconv.Itoa(n) }
