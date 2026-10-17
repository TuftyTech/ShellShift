package decode

import (
	"net/url"
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// urlParts is the shape shared by vless, trojan and hysteria2:
//
//	scheme://credential@host:port?query#label
//
// The predecessor repeated this preamble three times with small divergences. One
// implementation means one place to fix, and the differences between protocols become
// explicit instead of accidental.
type urlParts struct {
	Credential string
	Host       string
	Port       uint16
	Query      url.Values
	Label      string
}

func parseURLShape(rest string, rep *Repairs) (urlParts, error) {
	var p urlParts

	// Split the label off. The naive Cut at the first "#" is wrong when the credential
	// itself contains an unencoded "#", which RFC 3986 forbids but real producers emit
	// anyway: a trojan password of "fHngvzC1ut#YqsV4X" in the real corpus truncated the
	// URI to nothing and the node was rejected as credential-less. So the fragment
	// begins at the first "#" that appears after the authority (INV-46).
	body, label := splitFragment(rest, rep)
	if decoded, err := url.QueryUnescape(label); err == nil {
		label = decoded
	}
	p.Label = label

	body, rawQuery, _ := strings.Cut(body, "?")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		// A malformed query is not fatal on its own: recover the pairs that do parse
		// rather than discarding a node over one bad escape.
		q = salvageQuery(rawQuery)
	}
	p.Query = q

	cred, authority, found := strings.Cut(body, "@")
	if !found {
		return p, reject(ReasonMissingCredential, "no credential before @")
	}
	if unescaped, err := url.QueryUnescape(cred); err == nil {
		cred = unescaped
	}
	p.Credential = strings.TrimSpace(cred)
	if p.Credential == "" {
		return p, reject(ReasonMissingCredential, "empty credential")
	}

	host, portStr, err := splitHostPort(authority)
	if err != nil {
		return p, err
	}
	if err := validateHost(host); err != nil {
		return p, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return p, err
	}
	p.Host = strings.Trim(host, "[]")
	p.Port = port
	return p, nil
}

// splitHostPort handles bracketed IPv6 literals, which is the case a naive
// LastIndex(":") gets wrong.
func splitHostPort(authority string) (host, port string, err error) {
	authority = strings.TrimSpace(strings.TrimSuffix(authority, "/"))
	if authority == "" {
		return "", "", reject(ReasonBadHost, "empty authority")
	}
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end < 0 {
			return "", "", reject(ReasonBadHost, "unterminated IPv6 literal")
		}
		host = authority[1:end]
		remainder := authority[end+1:]
		if !strings.HasPrefix(remainder, ":") {
			return "", "", reject(ReasonMissingPort, "no port after IPv6 literal")
		}
		return host, remainder[1:], nil
	}
	i := strings.LastIndex(authority, ":")
	if i < 0 {
		return "", "", reject(ReasonMissingPort, "no port in %q", authority)
	}
	return authority[:i], authority[i+1:], nil
}

// salvageQuery recovers the well-formed pairs from a query string that url.ParseQuery
// rejected as a whole.
func salvageQuery(raw string) url.Values {
	out := url.Values{}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if k == "" {
			continue
		}
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		out.Set(k, v)
	}
	return out
}

// first returns the first non-empty value among the named query keys, checked
// case-insensitively because feeds are inconsistent about capitalisation.
func (p urlParts) first(keys ...string) string {
	lowered := make(map[string]string, len(p.Query))
	for k, vs := range p.Query {
		if len(vs) > 0 && vs[0] != "" {
			lowered[strings.ToLower(k)] = vs[0]
		}
	}
	for _, k := range keys {
		if v, ok := lowered[strings.ToLower(k)]; ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// narrowFingerprint maps a requested uTLS fingerprint onto the supported set.
// An unsupported value becomes the default rather than failing the node (INV-17).
func narrowFingerprint(requested string, sec model.Security) string {
	if sec == model.SecurityNone {
		return ""
	}
	fp := strings.ToLower(strings.TrimSpace(requested))
	if fp != "" && model.Fingerprints[fp] {
		return fp
	}
	return model.DefaultFingerprint
}

// splitALPN parses a comma-separated ALPN list, defaulting for TLS-bearing nodes.
func splitALPN(raw string, sec model.Security) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 && sec != model.SecurityNone {
		return []string{"h2", "http/1.1"}
	}
	return out
}

// splitFragment separates the body from the label, tolerating an unencoded "#" inside
// the credential.
//
// The authority ends at the last "@" before any query string. A "#" occurring before
// that point cannot be a fragment delimiter, because a fragment is by definition the
// final component; it can only be a character the producer failed to encode.
func splitFragment(rest string, rep *Repairs) (body, label string) {
	scan := rest
	if q := strings.IndexByte(scan, 63); q >= 0 { // 63 is the question mark
		scan = scan[:q]
	}
	authorityEnd := strings.LastIndexByte(scan, 64) // 64 is the at sign
	if authorityEnd < 0 {
		authorityEnd = 0
	}

	if hash := strings.IndexByte(rest[authorityEnd:], 35); hash >= 0 { // 35 is the hash
		cut := authorityEnd + hash
		if cut > 0 && strings.IndexByte(rest[:cut], 35) >= 0 {
			// A hash appeared inside the credential and was tolerated.
			rep.HTMLEntities++
		}
		return rest[:cut], rest[cut+1:]
	}
	return rest, ""
}

// carried extracts the parameters this project does not act on but a visitor client may.
//
// The set is named in model.PassThrough rather than open. Measurement is what put this here:
// republishing 100 distinct parameter shapes from a real catalogue dropped a Reality spiderX
// value on twelve of them, which sing-box ignores and Xray-based clients use.
func (p urlParts) carried() map[string]string {
	var out map[string]string
	for key, values := range p.Query {
		if len(values) == 0 {
			continue
		}
		clean, ok := model.CarryParam(key, values[0])
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[strings.ToLower(key)] = clean
	}
	return model.TrimCarried(out)
}
