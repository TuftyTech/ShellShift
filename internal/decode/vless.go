package decode

import (
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// uuidPattern-free check: VLESS and VMess credentials must be UUIDs, and a
// hand-rolled scan is both faster and clearer than a regexp for a fixed shape
// (GHOST-004).
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

func decodeVLESS(rest string, rep *Repairs) (model.Node, error) {
	p, err := parseURLShape(rest, rep)
	if err != nil {
		return model.Node{}, err
	}
	if !isUUID(p.Credential) {
		return model.Node{}, reject(ReasonBadUUID, "credential is not a UUID")
	}

	sec, err := model.ParseSecurity(strings.ToLower(p.first("security")))
	if err != nil {
		return model.Node{}, reject(ReasonUnknownSecurity, "%v", err)
	}
	transport := model.ParseTransport(strings.ToLower(p.first("type", "net")))

	if requiresTunnellingTransport(model.ProtoVLESS, sec, transport) {
		return model.Node{}, reject(ReasonPlaintextNoTunnel,
			"plaintext vless over %s", transport)
	}

	host := p.first("host")
	path := p.first("path")
	serviceName := p.first("serviceName", "servicename")
	if transport == model.TransportGRPC && serviceName == "" {
		// The gRPC service name doubles as the path in many feeds. sing-box wants the
		// key present even when empty, so an empty string is a value here, not a gap.
		serviceName = path
	}

	id := model.Identity{
		Protocol:   model.ProtoVLESS,
		Server:     p.Host,
		Port:       p.Port,
		Credential: p.Credential,
		Transport:  transport,
		Security:   sec,
		Host:       host,
		Path:       path,
	}

	if transport == model.TransportGRPC {
		id.Path = serviceName
	}

	if sec == model.SecurityReality {
		pbk := p.first("pbk", "publicKey", "public-key")
		if err := validateRealityKey(pbk); err != nil {
			return model.Node{}, err
		}
		id.PublicKey = strings.TrimSpace(pbk)
		id.ShortID = canonicalShortID(p.first("sid", "shortId", "short-id"))
	}

	id.SNI = resolveSNI(p.first("sni", "peer"), host, p.Host, transport, sec)

	node := model.Node{
		Identity:    id,
		Fingerprint: narrowFingerprint(p.first("fp"), sec),
		ALPN:        splitALPN(p.first("alpn"), sec),
		Flow:        resolveFlow(p.first("flow"), transport, sec),
		Carried:     p.carried(),
	}
	// UDP packet encoding reaches the engine, so it is modelled rather than carried. The
	// values sing-box accepts are a closed set; anything else is ignored rather than passed on.
	switch strings.ToLower(p.first("packetEncoding", "packetencoding")) {
	case "xudp", "packetaddr":
		node.PacketEncoding = strings.ToLower(p.first("packetEncoding", "packetencoding"))
	}
	return node, nil
}
