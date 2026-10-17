package decode

import "strings"

// garbageMarkers are substrings that mark a candidate as a placeholder, a test entry or
// a honeypot rather than a real endpoint. The set was assembled empirically by the
// predecessor from feeds that publish filler alongside real configurations.
//
// The check is case-insensitive and applies both to the raw URI and to the decoded
// VMess label, because the marker frequently appears only in the human-readable name
// inside the base64 payload (GHOST-007).
var garbageMarkers = []string{
	"01010101",
	"9292929",
	"11111111-1111",
	"test1",
	"pwn1337",
	"rootface",
}

// isGarbage reports whether any marker appears in s.
func isGarbage(s string) bool {
	lower := strings.ToLower(s)
	for _, m := range garbageMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
