package tunnel

import (
	"fmt"
	"net/netip"

	"github.com/tuftytech/shellshift/internal/model"
)

// CheckBuild verifies that this binary was built with the tags the project depends on.
//
// It exists because of a failure mode that is silent and catastrophic. sing-box gates
// uTLS behind the with_utls build tag, and the Reality client is inside that same gate.
// Without the tag, every Reality node fails to construct with an error — and since each
// node is isolated, the run does not crash: it just drops them. In the real corpus that
// is 540 of 865 nodes, sixty-two percent of the catalogue, disappearing in a way that
// looks exactly like the upstream feeds getting worse (INV-49).
//
// So the check runs once at startup and refuses to continue, rather than letting the
// run produce a plausible-looking but gutted result.
func CheckBuild() error {
	d := NewInProcess(Config{})
	defer d.Close()

	// A Reality node is the probe: it exercises uTLS, which is the gated dependency.
	probe := model.Node{
		Identity: model.Identity{
			Protocol:   model.ProtoVLESS,
			Server:     "example.com",
			Port:       443,
			Credential: "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b",
			Transport:  model.TransportTCP,
			Security:   model.SecurityReality,
			SNI:        "www.example.com",
			PublicKey:  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		},
		Fingerprint: model.DefaultFingerprint,
	}
	target := Target{Node: probe, Server: netip.MustParseAddr("203.0.113.1")}

	out, err := d.newOutbound(d.ctx, d.logger, target)
	if err != nil {
		return fmt.Errorf(
			"this binary cannot construct Reality outbounds, which is most of the catalogue: %w"+
				" (build with: go build -tags with_utls)", err)
	}
	closeOutbound(out)
	return nil
}
