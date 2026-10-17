// Package decode turns untrusted proxy URIs into validated nodes.
package decode

import (
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// Result is one successfully decoded node plus what it cost to read it.
type Result struct {
	Node    model.Node
	Repairs Repairs
}

// Decode parses a single proxy URI.
//
// The contract is deliberately narrow: either a fully validated node comes back, or an
// error carrying a countable Reason. There is no partial success and no coercion to a
// default — the predecessor filled in a port of 443 for unreadable input, which
// produced nodes that could never work and could not be told apart from real ones.
func Decode(uri string) (Result, error) {
	var rep Repairs

	line := strings.TrimSpace(uri)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return Result{}, reject(ReasonNotAURI, "blank or comment")
	}

	// Feeds are frequently scraped out of HTML, so entities and a stray slash before
	// the query string are common and harmless to repair. Only the entities that
	// HTML-escaping a URI actually produces are reversed — see entities.go for the
	// real corpus failure a general decoder causes.
	if unescaped, changed := unescapeURIEntities(line); changed {
		line = unescaped
		rep.HTMLEntities++
	}
	if strings.Contains(line, "/?") {
		line = strings.Replace(line, "/?", "?", 1)
		rep.QuerySeparator++
	}

	scheme, rest, found := strings.Cut(line, "://")
	if !found {
		return Result{}, reject(ReasonNotAURI, "no scheme separator")
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))

	// hy2 is an accepted abbreviation. Rewriting it before any URL parsing is what
	// makes the authority and port readable at all.
	if scheme == "hy2" {
		rep.SchemeRewrite++
	}

	proto, ok := model.ProtocolForScheme(scheme)
	if !ok {
		return Result{}, reject(ReasonUnknownScheme, "%q", scheme)
	}

	// The marker check runs on the whole line before any decoding, and again inside the
	// VMess decoder once the label is readable.
	if isGarbage(line) {
		return Result{}, reject(ReasonGarbageMarker, "marker in URI")
	}

	var (
		node model.Node
		err  error
	)
	switch proto {
	case model.ProtoVLESS:
		node, err = decodeVLESS(rest, &rep)
	case model.ProtoVMess:
		node, err = decodeVMess(rest, &rep)
	case model.ProtoTrojan:
		node, err = decodeTrojan(rest, &rep)
	case model.ProtoShadowsocks:
		node, err = decodeShadowsocks(rest, &rep)
	case model.ProtoHysteria2:
		node, err = decodeHysteria2(rest, &rep)
	default:
		return Result{}, reject(ReasonUnknownScheme, "%q has no decoder", proto)
	}
	if err != nil {
		return Result{}, err
	}

	return Result{Node: node, Repairs: rep}, nil
}
