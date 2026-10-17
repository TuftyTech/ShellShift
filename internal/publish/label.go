package publish

import (
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// Label renders the name a client shows for a node: flag, place, short code.
//
//	🇯🇵 Japan · Tokyo · 3f2a1b0c
//	🇷🇺 Russia · St Petersburg · a71e0044
//	Japan · 5c9d2e11                        (country known, city not)
//	· 88b41f02                              (nothing known but the code)
//
// Three parts, and each is there for a reason a user would recognise. The flag is what makes a
// list of a hundred entries scannable. The place is what makes two entries in the same country
// distinguishable, which a country code alone does not. The code is what makes every entry
// unique — and uniqueness is not decoration: a client that keys its profiles by name silently
// collapses duplicates, so two nodes sharing a label means the user loses one of them.
func Label(n model.Node, code string) string {
	// Sanitised here as well as at the geo boundary, and not because the boundary is untrusted.
	// The rule being enforced is different: the boundary bounds what gets stored, this bounds what
	// a subscription line may contain. A label carrying a newline splits one entry into two, and
	// that must be impossible regardless of how the node acquired its fields.
	city := safeForLabel(n.City)
	place := safeForLabel(n.CountryName)
	if place == "" {
		// Falling back to the code keeps the entry identifiable rather than nameless. It is not a
		// placeholder for an unknown country: an absent country produces no part at all.
		place = safeForLabel(n.Country)
	}
	if city != "" && !strings.EqualFold(city, place) {
		// A city equal to the country name is common — Singapore, Luxembourg — and repeating it
		// reads as a mistake.
		if place != "" {
			place += " · " + city
		} else {
			place = city
		}
	}
	// The flag attaches to the place rather than standing as a field of its own: "🇯🇵 Japan" is one
	// thing named twice, and separating them reads as two.
	var parts []string
	if flag := Flag(n.Country); flag != "" {
		if place != "" {
			parts = append(parts, flag+" "+place)
		} else {
			parts = append(parts, flag)
		}
	} else if place != "" {
		parts = append(parts, place)
	}
	if code != "" {
		parts = append(parts, code)
	}
	return strings.Join(parts, " · ")
}

// safeForLabel strips what would corrupt a subscription line or collide with the separator.
func safeForLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f: // control characters, including CR and LF
			return -1
		case r == '·': // the separator itself
			return -1
		case r == '#': // would open a fragment in a published URI
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// Flag turns a two-letter country code into its regional-indicator emoji.
//
// The two characters are offset into the regional indicator block, which is how every flag emoji
// is composed, so no table of flags is needed and a code this does not recognise produces nothing
// rather than a wrong flag.
func Flag(cc string) string {
	if len(cc) != 2 {
		return ""
	}
	cc = strings.ToUpper(cc)
	var out []rune
	for _, c := range cc {
		if c < 'A' || c > 'Z' {
			return ""
		}
		out = append(out, rune(0x1F1E6+(c-'A')))
	}
	return string(out)
}

// ShortCodes assigns every entry the shortest identity prefix that is unique across the set.
//
// The identity hash is already unique, but a truncation of it is not, and the truncation is what
// goes in the label. Eight hex characters is 32 bits: at a hundred thousand published nodes the
// chance of at least one collision is about 68 percent, and a collision means two entries share a
// name and a client that keys profiles by name keeps one of them.
//
// So the length is measured rather than assumed. It starts at eight, which is what a person can
// read and compare, and grows only if the set actually needs it. One length is used for the whole
// set rather than per entry, because codes of differing lengths in one list look like a defect.
func ShortCodes(entries []Entry) map[string]string {
	keys := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		k := e.Node.Key()
		if seen[k] {
			// The same node twice is not a collision; it is the same node. Deduplication is the
			// pipeline's job and this must not mistake its absence for a length problem.
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return shortCodesFor(keys)
}

// shortCodesFor is ShortCodes over bare identity keys. Separated so the length rule can be tested
// against constructed collisions: identities are hashes, so a colliding pair cannot be built by
// choosing nodes.
func shortCodesFor(keys []string) map[string]string {
	const minLen, maxLen = 8, 64

	length := minLen
	for ; length < maxLen; length++ {
		used := make(map[string]bool, len(keys))
		clash := false
		for _, k := range keys {
			p := prefix(k, length)
			if used[p] {
				clash = true
				break
			}
			used[p] = true
		}
		if !clash {
			break
		}
	}

	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = prefix(k, length)
	}
	return out
}

func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
