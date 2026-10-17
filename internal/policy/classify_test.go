package policy

import (
	"context"
	"testing"

	"github.com/tuftytech/shellshift/internal/model"
)

func realityNode(sni string) model.Node {
	return model.Node{Identity: model.Identity{
		Protocol: model.ProtoVLESS, Server: "198.51.100.9", Port: 443,
		Credential: "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b",
		Transport:  model.TransportTCP, Security: model.SecurityReality,
		SNI: sni, PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	}}
}

// stubMasking answers a fixed verdict without touching the network.
type stubMasking struct{ ok bool }

func (s stubMasking) Prove(context.Context, string) (bool, error) { return s.ok, nil }

func classifierWith(wl *Whitelist, ok bool) *Classifier {
	c := NewClassifier(wl, nil)
	c.masking = stubMasking{ok: ok}
	return c
}

// The whitelist class is the product actual bet, and every condition below is part of it.
func TestClassificationConditions(t *testing.T) {
	wl := loaded(t, "cover.example.com\n", "")

	t.Run("reality with proven masking is whitelisted", func(t *testing.T) {
		class, reason := classifierWith(wl, true).Classify(context.Background(),
			realityNode("cover.example.com"))
		if class != model.ClassWhitelisted {
			t.Fatalf("class = %q, reason = %q", class, reason)
		}
	})

	// The predecessor asked only whether the name appeared in a list, which a node satisfies
	// by naming any popular domain it likes.
	t.Run("masking that cannot be proven is not whitelisted", func(t *testing.T) {
		class, reason := classifierWith(wl, false).Classify(context.Background(),
			realityNode("cover.example.com"))
		if class != model.ClassOpen {
			t.Fatalf("class = %q, want open", class)
		}
		if reason != ReasonMaskingUnproven {
			t.Fatalf("reason = %q, want %q", reason, ReasonMaskingUnproven)
		}
	})

	t.Run("a name outside the whitelist is not whitelisted", func(t *testing.T) {
		class, reason := classifierWith(wl, true).Classify(context.Background(),
			realityNode("elsewhere.example.org"))
		if class != model.ClassOpen || reason != ReasonNotInWhitelist {
			t.Fatalf("class = %q, reason = %q", class, reason)
		}
	})

	// The class is about a disguise only Reality provides.
	t.Run("a non-reality node is never whitelisted", func(t *testing.T) {
		n := realityNode("cover.example.com")
		n.Identity.Security = model.SecurityTLS
		class, reason := classifierWith(wl, true).Classify(context.Background(), n)
		if class != model.ClassOpen || reason != ReasonNotReality {
			t.Fatalf("class = %q, reason = %q", class, reason)
		}
	})

	// An outage must not silently promote the catalogue, and must not demote it silently
	// either: the reason has to say what happened.
	t.Run("an unavailable whitelist reports itself", func(t *testing.T) {
		class, reason := classifierWith(NewWhitelist(), true).Classify(context.Background(),
			realityNode("cover.example.com"))
		if class != model.ClassOpen || reason != ReasonListUnavailable {
			t.Fatalf("class = %q, reason = %q", class, reason)
		}
	})

	// A classifier with no masking prover at all must not quietly fall back to the weaker
	// rule: that is how a check gets built and then never runs.
	t.Run("a missing prover is not a pass", func(t *testing.T) {
		c := NewClassifier(wl, nil)
		class, reason := c.Classify(context.Background(), realityNode("cover.example.com"))
		if class != model.ClassOpen || reason != ReasonMaskingUnproven {
			t.Fatalf("class = %q, reason = %q", class, reason)
		}
	})
}

// The relaxed rule exists only so the difference can be measured, and it has to be asked for
// explicitly.
func TestRelaxedRuleMustBeAskedFor(t *testing.T) {
	wl := loaded(t, "cover.example.com\n", "")
	c := NewClassifier(wl, nil)
	c.RequireMaskingProof = false

	class, reason := c.Classify(context.Background(), realityNode("cover.example.com"))
	if class != model.ClassWhitelisted || reason != ReasonWhitelisted {
		t.Fatalf("class = %q, reason = %q", class, reason)
	}
}
