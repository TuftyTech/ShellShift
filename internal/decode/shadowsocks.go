package decode

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// decodeShadowsocks reads the three credential encodings that appear in the wild:
//
//	ss://base64(method:password)@host:port
//	ss://method:password@host:port
//	ss://base64(method:password@host:port)
//
// The fragment is removed before the query is parsed, and both "?" and "/?" are
// accepted as the separator, because feeds use both (INV-28).
func decodeShadowsocks(rest string, rep *Repairs) (model.Node, error) {
	body, _, _ := strings.Cut(rest, "#")

	body, rawQuery, _ := strings.Cut(body, "?")
	query := salvageQuery(rawQuery)
	body = strings.TrimSuffix(strings.TrimSpace(body), "/")

	method, password, host, portStr, err := splitShadowsocksBody(body, rep)
	if err != nil {
		return model.Node{}, err
	}

	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" || password == "" {
		return model.Node{}, reject(ReasonMissingCredential, "shadowsocks needs method and password")
	}
	if !model.ShadowsocksMethods[method] {
		return model.Node{}, reject(ReasonUnsupportedCipher, "%q", method)
	}

	// A 2022-blake3 cipher requires a pre-shared key of an exact byte length. A wrong
	// key is a fatal sing-box start rather than a connection failure, so it is checked
	// here where the cost is one rejected node (INV-06).
	if want, needs := model.KeyLenForMethod(method); needs {
		if err := validatePSK(password, want); err != nil {
			return model.Node{}, err
		}
	}

	if err := validateHost(host); err != nil {
		return model.Node{}, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return model.Node{}, err
	}

	id := model.Identity{
		Protocol:   model.ProtoShadowsocks,
		Server:     strings.Trim(host, "[]"),
		Port:       port,
		Credential: password,
		Method:     method,
		// Shadowsocks accepts neither a v2ray transport nor a TLS block, so both are
		// fixed rather than read from the link (INV-08).
		Transport: model.TransportTCP,
		Security:  model.SecurityNone,
	}

	node := model.Node{Identity: id, Carried: carriedFromValues(query)}

	// SIP003. sing-box implements only obfs-local and v2ray-plugin; anything else means
	// the node cannot be honestly tested, so it is dropped rather than attempted
	// without its plugin (INV-07).
	if raw := firstQuery(query, "plugin"); raw != "" {
		name, opts, order, perr := parseSIP003(raw)
		if perr != nil {
			return model.Node{}, perr
		}
		node.Identity.Plugin = name
		node.PluginOpts = opts
		node.PluginOptOrder = order
	}

	return node, nil
}

func splitShadowsocksBody(body string, rep *Repairs) (method, password, host, port string, err error) {
	if body == "" {
		return "", "", "", "", reject(ReasonBadPayload, "empty shadowsocks body")
	}

	if cred, authority, found := strings.Cut(body, "@"); found {
		// Forms 1 and 2: the authority is already readable.
		host, port, err = splitHostPort(authority)
		if err != nil {
			return "", "", "", "", err
		}
		if unescaped, uerr := url.QueryUnescape(cred); uerr == nil {
			cred = unescaped
		}
		// Form 2 is discriminated structurally, not by cipher allowlist membership:
		// base64 has no colon in its alphabet, so a colon here means the credential is
		// plaintext. Using the allowlist to detect the *form* made an unsupported
		// cipher masquerade as a broken payload, reporting the wrong reason.
		if m, p, ok := strings.Cut(cred, ":"); ok {
			return m, p, host, port, nil
		}
		// Form 1: the credential is base64.
		raw, derr := decodeBase64(cred, rep)
		if derr != nil {
			return "", "", "", "", derr
		}
		m, p, ok := strings.Cut(string(raw), ":")
		if !ok {
			return "", "", "", "", reject(ReasonBadPayload, "credential is not method:password")
		}
		return m, p, host, port, nil
	}

	// Form 3: the whole thing is base64.
	raw, derr := decodeBase64(body, rep)
	if derr != nil {
		return "", "", "", "", reject(ReasonBadPayload, "not method:password@host:port and not base64")
	}
	inner := string(raw)
	cred, authority, found := strings.Cut(inner, "@")
	if !found {
		return "", "", "", "", reject(ReasonBadPayload, "decoded payload has no @")
	}
	host, port, err = splitHostPort(authority)
	if err != nil {
		return "", "", "", "", err
	}
	m, p, ok := strings.Cut(cred, ":")
	if !ok {
		return "", "", "", "", reject(ReasonBadPayload, "decoded credential is not method:password")
	}
	return m, p, host, port, nil
}

// validatePSK checks a Shadowsocks-2022 pre-shared key.
//
// The multi-user form is "serverPSK:userPSK", and it is the last segment that must
// match the cipher key length.
func validatePSK(password string, want int) error {
	psk := password
	if i := strings.LastIndex(psk, ":"); i >= 0 {
		psk = psk[i+1:]
	}
	raw, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(psk); err != nil {
			return reject(ReasonBadPSKLength, "pre-shared key is not base64")
		}
	}
	if len(raw) != want {
		return reject(ReasonBadPSKLength, "pre-shared key is %d bytes, cipher needs %d", len(raw), want)
	}
	return nil
}

// parseSIP003 splits "name;key=value;flag" into a canonical plugin name and its
// options. Options are returned as a map rather than the original string so that a
// value can be validated and re-emitted, instead of being forwarded verbatim into a
// configuration the way the predecessor did.
func parseSIP003(raw string) (name string, opts map[string]string, order []string, err error) {
	rawName, tail, _ := strings.Cut(raw, ";")
	canonical, ok := model.SIP003Plugins[strings.ToLower(strings.TrimSpace(rawName))]
	if !ok {
		return "", nil, nil, reject(ReasonUnsupportedPlugin, "SIP003 plugin %q", rawName)
	}

	// Order is preserved rather than sorted. Sorting would still be deterministic, but a
	// SIP003 option list is written by a producer and read by a client, and the faithful thing
	// is to hand the client back what the producer wrote.
	opts = map[string]string{}
	for _, part := range strings.Split(tail, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, hasValue := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, seen := opts[k]; !seen {
			order = append(order, k)
		}
		if !hasValue {
			opts[k] = ""
			continue
		}
		opts[k] = strings.TrimSpace(v)
	}
	return canonical, opts, order, nil
}

func firstQuery(q url.Values, key string) string {
	for k, vs := range q {
		if strings.EqualFold(k, key) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// carriedFromValues collects the carried parameters from an already-parsed query.
//
// Shadowsocks does not go through the shared URL-shape parser, and that difference is exactly
// how a Shadowsocks-specific parameter went missing: a real corpus node carried a prefix value
// that nothing in the pipeline dropped deliberately, it simply had no path through.
func carriedFromValues(q url.Values) map[string]string {
	var out map[string]string
	for key, values := range q {
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
