package decode

import "strings"

// uriEntities are the only HTML entities that appear when a URI is HTML-escaped for
// embedding in a page, which is how feeds scraped from web pages arrive.
//
// A general-purpose entity decoder must NOT be used here, and this is not a
// theoretical concern: running 865 real published nodes through a full
// html.UnescapeString turned the query string
//
//	?type=tcp&note=volt_network
//
// into
//
//	?type=tcp¬e=volt_network
//
// because "&not" is itself a valid entity for the negation sign. The transport then
// became an unknown value, silently degraded to TCP, and two distinct nodes collapsed
// into one identity. The predecessor had the same bug and shipped both nodes.
//
// Replacing only these six sequences is sufficient and cannot corrupt a parameter name
// that merely begins with an entity-like prefix.
var uriEntities = strings.NewReplacer(
	"&amp;", "&",
	"&lt;", "<",
	"&gt;", ">",
	"&quot;", `"`,
	"&#39;", "'",
	"&#x2F;", "/",
)

// unescapeURIEntities reverses HTML escaping of a URI, and reports whether anything
// changed so the repair can be counted (INV-28, INV-46).
func unescapeURIEntities(s string) (string, bool) {
	if !strings.Contains(s, "&") {
		return s, false
	}
	out := uriEntities.Replace(s)
	return out, out != s
}
