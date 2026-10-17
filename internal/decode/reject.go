package decode

import "fmt"

// Reason classifies why a candidate was rejected. Rejections are counted by reason
// rather than merely logged: the predecessor could not distinguish "the source served
// garbage" from "we failed to parse valid input", so a parser regression looked
// exactly like upstream churn — fewer nodes today, no signal as to why.
type Reason string

const (
	ReasonNotAURI           Reason = "not_a_uri"
	ReasonUnknownScheme     Reason = "unknown_scheme"
	ReasonGarbageMarker     Reason = "garbage_marker"
	ReasonBadHost           Reason = "bad_host"
	ReasonMissingPort       Reason = "missing_port"
	ReasonBadPort           Reason = "bad_port"
	ReasonMissingCredential Reason = "missing_credential"
	ReasonBadUUID           Reason = "bad_uuid"
	ReasonBadPayload        Reason = "bad_payload"
	ReasonUnsupportedCipher Reason = "unsupported_cipher"
	ReasonBadPSKLength      Reason = "bad_psk_length"
	ReasonBadRealityKey     Reason = "bad_reality_key"
	ReasonUnsupportedPlugin Reason = "unsupported_plugin"
	ReasonBadPortRange      Reason = "bad_port_range"
	ReasonPlaintextNoTunnel Reason = "plaintext_without_tunnelling_transport"
	ReasonUnknownSecurity   Reason = "unknown_security"
)

// Error is a rejection with a machine-countable reason and a human explanation.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Detail
}

func reject(r Reason, format string, args ...any) error {
	return &Error{Reason: r, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf extracts the reason from an error produced by this package.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if as(err, &e) {
		return e.Reason, true
	}
	return "", false
}

// as is errors.As without the import, kept local so this file has no dependencies
// beyond fmt.
func as(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
