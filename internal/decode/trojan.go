package decode

import (
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

func decodeTrojan(rest string, rep *Repairs) (model.Node, error) {
	p, err := parseURLShape(rest, rep)
	if err != nil {
		return model.Node{}, err
	}
	// Trojan authenticates with a password, not a UUID, so any non-empty credential is
	// structurally acceptable (GHOST-005).

	rawSecurity := strings.ToLower(p.first("security"))
	if rawSecurity == "" {
		// Trojan is TLS-only by design; a feed that omits the parameter means TLS.
		rawSecurity = "tls"
	}
	sec, err := model.ParseSecurity(rawSecurity)
	if err != nil {
		return model.Node{}, reject(ReasonUnknownSecurity, "%v", err)
	}
	transport := model.ParseTransport(strings.ToLower(p.first("type", "net")))

	if requiresTunnellingTransport(model.ProtoTrojan, sec, transport) {
		return model.Node{}, reject(ReasonPlaintextNoTunnel,
			"plaintext trojan over %s", transport)
	}

	host := p.first("host")
	path := p.first("path")
	serviceName := p.first("serviceName", "servicename")
	if transport == model.TransportGRPC && serviceName == "" {
		serviceName = path
	}

	id := model.Identity{
		Protocol:   model.ProtoTrojan,
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
		pbk := p.first("pbk", "publicKey")
		if err := validateRealityKey(pbk); err != nil {
			return model.Node{}, err
		}
		id.PublicKey = strings.TrimSpace(pbk)
		id.ShortID = canonicalShortID(p.first("sid", "shortId"))
	}
	id.SNI = resolveSNI(p.first("sni", "peer"), host, p.Host, transport, sec)

	return model.Node{
		Identity:    id,
		Fingerprint: narrowFingerprint(p.first("fp"), sec),
		ALPN:        splitALPN(p.first("alpn"), sec),
		Carried:     p.carried(),
	}, nil
}
