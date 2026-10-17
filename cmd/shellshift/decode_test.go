package main

import (
	"testing"

	"github.com/tuftytech/shellshift/internal/model"
)

// The reported encryption must answer "what protects the hop to the node", not "what is in the
// security parameter". Shadowsocks has no TLS layer and is encrypted anyway, by its own cipher;
// reporting it as "none" would make an encrypted node indistinguishable from a plaintext one in
// the one diagnostic a person uses to check exactly that.
func TestChannelEncryption(t *testing.T) {
	cases := []struct {
		name string
		node model.Node
		want string
	}{
		{
			"shadowsocks reports its cipher, not the absent TLS layer",
			model.Node{Identity: model.Identity{
				Protocol: model.ProtoShadowsocks, Security: model.SecurityNone,
				Method: "chacha20-ietf-poly1305",
			}},
			"chacha20-ietf-poly1305",
		},
		{
			"hysteria2 is TLS by definition",
			model.Node{Identity: model.Identity{Protocol: model.ProtoHysteria2}},
			"tls (quic)",
		},
		{
			"vless without TLS is named as the finding it is",
			model.Node{Identity: model.Identity{
				Protocol: model.ProtoVLESS, Security: model.SecurityNone,
				Transport: model.TransportWebSocket,
			}},
			"NONE — readable on the wire",
		},
		{
			"vless with reality",
			model.Node{Identity: model.Identity{
				Protocol: model.ProtoVLESS, Security: model.SecurityReality,
			}},
			"reality",
		},
		{
			"trojan with tls",
			model.Node{Identity: model.Identity{
				Protocol: model.ProtoTrojan, Security: model.SecurityTLS,
			}},
			"tls",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := channelEncryption(tc.node); got != tc.want {
				t.Fatalf("channelEncryption = %q, want %q", got, tc.want)
			}
		})
	}
}

// INV-47. The label is the fragment, and the fragment begins at the LAST "#", not the first: a
// credential may carry an unencoded one. A real trojan password of the form "xxxx#yyyy" in the
// corpus was once truncated to nothing by cutting at the first.
func TestLabelOf(t *testing.T) {
	cases := []struct{ name, line, want string }{
		{
			"percent-encoded flag and place",
			"vless://c@a.example.com:443?security=tls#%F0%9F%87%AF%F0%9F%87%B5%20Japan%20%C2%B7%20Tokyo%20%C2%B7%203f2a1b0c",
			"🇯🇵 Japan · Tokyo · 3f2a1b0c",
		},
		{
			"a hash inside the credential is not the fragment",
			"trojan://pass#word@a.example.com:443?security=tls#%F0%9F%87%B7%F0%9F%87%BA%20Russia%20%C2%B7%20a71e0044",
			"🇷🇺 Russia · a71e0044",
		},
		{
			"no label at all is stated rather than shown as empty",
			"vless://c@a.example.com:443?security=tls",
			"(no label)",
		},
		{
			// A fragment that will not decode is shown verbatim: that is the finding, and hiding
			// it would turn a broken label into a missing one.
			"an undecodable fragment is shown as it stands",
			"vless://c@a.example.com:443?security=tls#%zz",
			"%zz",
		},
		{
			"a plain label needs no decoding",
			"vless://c@a.example.com:443?security=tls#c0ffee11",
			"c0ffee11",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := labelOf(tc.line); got != tc.want {
				t.Fatalf("labelOf = %q, want %q", got, tc.want)
			}
		})
	}
}
