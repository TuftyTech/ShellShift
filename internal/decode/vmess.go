package decode

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// vmessPayload is the base64-wrapped JSON object VMess links carry. Every field is a
// json.RawMessage-free permissive type because producers disagree about whether numbers
// are numbers: "port" and "aid" appear as both strings and integers in the wild.
type vmessPayload struct {
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
	PS   string `json:"ps"`
	SCY  string `json:"scy"`
}

func decodeVMess(rest string, rep *Repairs) (model.Node, error) {
	// The label lives inside the payload rather than after a fragment, so anything
	// after a "#" here is noise from a concatenated feed line.
	body, _, _ := strings.Cut(rest, "#")

	raw, err := decodeBase64(strings.TrimSpace(body), rep)
	if err != nil {
		return model.Node{}, err
	}

	var pl vmessPayload
	if err := json.Unmarshal(raw, &pl); err != nil {
		return model.Node{}, reject(ReasonBadPayload, "vmess json: %v", err)
	}

	// The marker frequently appears only in the human-readable label inside the
	// payload, which is invisible until now (GHOST-007).
	if isGarbage(pl.PS) {
		return model.Node{}, reject(ReasonGarbageMarker, "marker in vmess label")
	}

	if !isUUID(strings.TrimSpace(pl.ID)) {
		return model.Node{}, reject(ReasonBadUUID, "vmess id is not a UUID")
	}
	if err := validateHost(pl.Add); err != nil {
		return model.Node{}, err
	}
	port, err := parsePort(anyToString(pl.Port))
	if err != nil {
		return model.Node{}, err
	}

	sec := model.SecurityNone
	if isTruthy(pl.TLS) {
		sec = model.SecurityTLS
	}
	transport := model.ParseTransport(strings.ToLower(strings.TrimSpace(pl.Net)))

	if requiresTunnellingTransport(model.ProtoVMess, sec, transport) {
		return model.Node{}, reject(ReasonPlaintextNoTunnel,
			"plaintext vmess over %s", transport)
	}

	id := model.Identity{
		Protocol:   model.ProtoVMess,
		Server:     strings.Trim(strings.TrimSpace(pl.Add), "[]"),
		Port:       port,
		Credential: strings.TrimSpace(pl.ID),
		Transport:  transport,
		Security:   sec,
		Host:       strings.TrimSpace(pl.Host),
		Path:       strings.TrimSpace(pl.Path),
	}
	if transport == model.TransportGRPC && id.Path == "" {
		id.Path = strings.TrimSpace(pl.Path)
	}
	id.SNI = resolveSNI(pl.SNI, pl.Host, id.Server, transport, sec)

	return model.Node{
		Identity:    id,
		Fingerprint: narrowFingerprint(pl.FP, sec),
		ALPN:        splitALPN(pl.ALPN, sec),
		AlterID:     coerceAlterID(pl.Aid),
	}, nil
}

// anyToString renders a JSON value that may legitimately be a string or a number.
func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return ""
	}
}

// coerceAlterID reads the VMess alterId, which producers write as a string, a number,
// or nonsense. A value that is not a non-negative integer becomes zero, which is what
// modern VMess wants anyway (INV-03).
func coerceAlterID(v any) int {
	s := anyToString(v)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// isTruthy interprets the VMess tls field, which is a string that means true when it
// says so in any of several ways.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tls", "1", "true", "reality":
		return true
	}
	return false
}
