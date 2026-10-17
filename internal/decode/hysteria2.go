package decode

import (
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

func decodeHysteria2(rest string, rep *Repairs) (model.Node, error) {
	p, err := parseURLShape(rest, rep)
	if err != nil {
		return model.Node{}, err
	}

	// Hysteria2 rides QUIC and is always TLS. There is no plaintext variant, so the
	// security mode is not read from the query at all.
	id := model.Identity{
		Protocol:   model.ProtoHysteria2,
		Server:     p.Host,
		Port:       p.Port,
		Credential: p.Credential,
		Transport:  model.TransportQUIC,
		Security:   model.SecurityTLS,
	}

	// Port hopping. sing-box wants a range list and treats it as conflicting with a
	// single server port, so the caller must clear that; here the range simply becomes
	// part of the identity, which is also what stops two hopping nodes on the same
	// first port from being confused (INV-09, INV-21).
	if spec := p.first("mport", "ports", "server_ports"); spec != "" {
		canonical, err := canonicalPortRange(spec)
		if err != nil {
			return model.Node{}, err
		}
		id.PortRange = canonical
	}

	id.SNI = resolveSNI(p.first("sni", "peer"), p.first("host"), p.Host,
		model.TransportQUIC, model.SecurityTLS)

	node := model.Node{
		Identity: id,
		ALPN:     splitALPN(p.first("alpn"), model.SecurityTLS),
		Carried:  p.carried(),
	}

	// Obfuscation is accepted only as salamander and only with a password. An unknown
	// type makes sing-box reject the configuration; a salamander entry missing its
	// password is kept without obfuscation so it can fail honestly rather than being
	// dropped on a guess (INV-10).
	obfs := strings.ToLower(strings.TrimSpace(p.first("obfs")))
	obfsPass := p.first("obfs-password", "obfsParam", "obfs_password")
	if obfs != "" && obfs != model.Hysteria2Obfuscation {
		return model.Node{}, reject(ReasonUnsupportedPlugin,
			"hysteria2 obfuscation %q is not supported", obfs)
	}
	if obfs == model.Hysteria2Obfuscation && obfsPass != "" {
		node.Obfuscation = model.Hysteria2Obfuscation
		node.ObfuscationPassword = obfsPass
	}

	return node, nil
}
