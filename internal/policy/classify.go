package policy

import (
	"context"

	"github.com/tuftytech/shellshift/internal/model"
)

// Classifier decides which bypass class a proven node belongs to.
type Classifier struct {
	Whitelist *Whitelist
	Masking   *MaskingProver
	// masking is the interface actually consulted, so a test can substitute a fixed verdict
	// without opening a socket.
	masking maskingProver
	// RequireMaskingProof gates the stricter rule. It is on by default; turning it off
	// reverts to the predecessor behaviour of trusting a list lookup alone, which is
	// available only so the difference can be measured.
	RequireMaskingProof bool
}

// maskingProver is the narrow contract the classifier needs.
type maskingProver interface {
	Prove(ctx context.Context, serverName string) (bool, error)
}

// NewClassifier builds a classifier.
func NewClassifier(wl *Whitelist, masking *MaskingProver) *Classifier {
	c := &Classifier{Whitelist: wl, Masking: masking, RequireMaskingProof: true}
	if masking != nil {
		c.masking = masking
	}
	return c
}

// Reason explains a classification, so a run can report why a class is smaller than expected
// instead of leaving it to be guessed.
type Reason string

const (
	ReasonWhitelisted     Reason = "whitelisted"
	ReasonNotReality      Reason = "not reality"
	ReasonNoServerName    Reason = "no server name"
	ReasonNotInWhitelist  Reason = "server name not in whitelist"
	ReasonMaskingUnproven Reason = "masking could not be proven"
	ReasonListUnavailable Reason = "whitelist unavailable"
)

// Classify returns the class and the reason for it.
//
// The whitelist class is the product actual bet: a Reality node whose server name belongs to
// a list the filtering regime lets through has a real chance of surviving inspection. Every
// condition below is part of that bet:
//
//   - Reality specifically, because the class is about a disguise only Reality provides.
//   - The server name in the whitelist, because that is what the regime lets through.
//   - The disguise proven real, because a node can name any popular domain it likes and the
//     predecessor asked for nothing more than the name.
func (c *Classifier) Classify(ctx context.Context, n model.Node) (model.Class, Reason) {
	if n.Identity.Security != model.SecurityReality {
		return model.ClassOpen, ReasonNotReality
	}
	if !c.Whitelist.Loaded() {
		// An outage must not silently reclassify the catalogue, and it must not silently
		// promote it either. Everything becomes open and the reason says why.
		return model.ClassOpen, ReasonListUnavailable
	}

	name := CoverName(n)
	if name == "" {
		return model.ClassOpen, ReasonNoServerName
	}

	if !c.Whitelist.Match(name) {
		return model.ClassOpen, ReasonNotInWhitelist
	}
	if !c.RequireMaskingProof {
		return model.ClassWhitelisted, ReasonWhitelisted
	}

	if c.masking == nil {
		return model.ClassOpen, ReasonMaskingUnproven
	}
	ok, err := c.masking.Prove(ctx, name)
	if err != nil || !ok {
		return model.ClassOpen, ReasonMaskingUnproven
	}
	return model.ClassWhitelisted, ReasonWhitelisted
}

// CoverName is the name a node claims to be, and therefore the name the masking proof is about.
//
// Exported and used by both the classifier and publication so there is one fallback chain rather
// than two: the certificate on a card has to be the certificate the class decision was made from,
// and a second copy of "SNI, then Host, then Server" is how those two quietly disagree.
func CoverName(n model.Node) string {
	if n.Identity.SNI != "" {
		return n.Identity.SNI
	}
	if n.Identity.Host != "" {
		return n.Identity.Host
	}
	return n.Identity.Server
}
