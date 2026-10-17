package decode

import (
	"encoding/base64"
	"net/netip"
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// resolveSNI applies the server-name fallback chain.
//
// Order: an explicit SNI, then the transport Host (but only for transports where the
// Host header is not the thing being sent as the server name), then the server itself.
// Whatever results, a value that parses as an IP address is discarded: an address is
// not a valid server name and offering one breaks the handshake (INV-18).
func resolveSNI(sni, host, server string, transport model.Transport, sec model.Security) string {
	candidates := []string{sni}
	if transport != model.TransportWebSocket && transport != model.TransportHTTPUpgrade &&
		transport != model.TransportHTTP2 {
		candidates = append(candidates, host)
	}
	// Reality never falls back to the server address: the whole point is that the
	// server name belongs to somebody else.
	if sec != model.SecurityReality {
		candidates = append(candidates, server)
	}

	for _, c := range candidates {
		v := strings.TrimSpace(c)
		if v == "" {
			continue
		}
		v = strings.Split(v, ",")[0]
		v = strings.Trim(v, "[] \t")
		if v == "" {
			continue
		}
		if _, err := netip.ParseAddr(v); err == nil {
			continue // an address cannot serve as a server name
		}
		return v
	}
	return ""
}

// realityKeyLen bounds the textual length of a Reality public key. The authoritative
// check is that it decodes to exactly 32 bytes; the length bound rejects obvious
// rubbish before doing the work.
const (
	realityKeyMinLen = 40
	realityKeyMaxLen = 46
	realityKeyBytes  = 32
)

// validateRealityKey checks a Reality public key.
//
// Both halves matter: the predecessor checked the decoded length in the parser and only
// the textual length in the engine, which is how the two disagreed. Here there is one
// check (INV-15).
func validateRealityKey(pbk string) error {
	k := strings.TrimSpace(pbk)
	if k == "" {
		return reject(ReasonBadRealityKey, "missing public key")
	}
	if len(k) < realityKeyMinLen || len(k) > realityKeyMaxLen {
		return reject(ReasonBadRealityKey, "length %d outside %d..%d", len(k), realityKeyMinLen, realityKeyMaxLen)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k, "="))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(k, "="))
	}
	if err != nil {
		return reject(ReasonBadRealityKey, "not base64url: %v", err)
	}
	if len(raw) != realityKeyBytes {
		return reject(ReasonBadRealityKey, "decodes to %d bytes, want %d", len(raw), realityKeyBytes)
	}
	return nil
}

// canonicalShortID normalises a Reality short id. The absent case is an empty string
// rather than a missing field, because sing-box wants the key present (INV-16).
func canonicalShortID(sid string) string {
	s := strings.TrimSpace(strings.ToLower(sid))
	switch s {
	case "none", "null", "undefined":
		return ""
	}
	return s
}

// resolveFlow decides whether a VLESS flow survives.
//
// xtls-rprx-vision is valid only over raw TCP. Paired with any v2ray transport,
// sing-box rejects the configuration outright — the failure that took down whole
// batches in the predecessor, tracked upstream as SagerNet/sing-box#3258. Clearing it
// here, once, is what keeps the dialed node and the published URI in agreement
// (INV-01).
func resolveFlow(flow string, transport model.Transport, sec model.Security) string {
	f := strings.TrimSpace(strings.ToLower(flow))
	if f == "" {
		return ""
	}
	if transport != model.TransportTCP {
		return ""
	}
	if sec == model.SecurityNone {
		return ""
	}
	return f
}

// requiresTunnellingTransport reports whether a plaintext node is still worth keeping.
//
// A vless/vmess/trojan node with no TLS is only plausible when it is wrapped in a
// transport that can carry it through a CDN; bare plaintext TCP is almost always a
// mis-transcribed entry (GHOST-011).
func requiresTunnellingTransport(proto model.Protocol, sec model.Security, t model.Transport) bool {
	if sec != model.SecurityNone {
		return false
	}
	switch proto {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan:
		return t != model.TransportWebSocket && t != model.TransportHTTPUpgrade
	}
	return false
}
