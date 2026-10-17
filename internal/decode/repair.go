package decode

import (
	"encoding/base64"
	"strings"
)

// Repairs counts the corrections applied while decoding. Decoding is tolerant of
// malformed input — public feeds are written by hand and by scripts of varying
// quality — but it is never silent: every repair is counted so that a rise in
// corrections is visible as its own signal rather than hiding inside a lower node
// count (INV-28).
type Repairs struct {
	Base64Padding  int
	Base64Alphabet int
	Whitespace     int
	HTMLEntities   int
	QuerySeparator int
	SchemeRewrite  int
}

// Total is the number of corrections applied.
func (r Repairs) Total() int {
	return r.Base64Padding + r.Base64Alphabet + r.Whitespace +
		r.HTMLEntities + r.QuerySeparator + r.SchemeRewrite
}

// Add accumulates another set of repairs.
func (r *Repairs) Add(o Repairs) {
	r.Base64Padding += o.Base64Padding
	r.Base64Alphabet += o.Base64Alphabet
	r.Whitespace += o.Whitespace
	r.HTMLEntities += o.HTMLEntities
	r.QuerySeparator += o.QuerySeparator
	r.SchemeRewrite += o.SchemeRewrite
}

// decodeBase64 decodes a base64 payload written by an arbitrary producer.
//
// Handled, each counted: the URL-safe alphabet used without saying so, embedded
// whitespace and newlines, and missing padding. Unlike the predecessor, a payload that
// cannot be decoded returns an error instead of the untouched input — returning the
// input silently turned a decode failure into a mysterious downstream parse failure.
func decodeBase64(s string, rep *Repairs) ([]byte, error) {
	cleaned := s
	if strings.ContainsAny(cleaned, " \t\r\n") {
		cleaned = strings.Map(func(r rune) rune {
			switch r {
			case ' ', '\t', '\r', '\n':
				return -1
			}
			return r
		}, cleaned)
		rep.Whitespace++
	}

	if strings.ContainsAny(cleaned, "-_") {
		cleaned = strings.NewReplacer("-", "+", "_", "/").Replace(cleaned)
		rep.Base64Alphabet++
	}

	if pad := len(cleaned) % 4; pad != 0 {
		cleaned += strings.Repeat("=", 4-pad)
		rep.Base64Padding++
	}

	out, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, reject(ReasonBadPayload, "base64: %v", err)
	}
	return out, nil
}
