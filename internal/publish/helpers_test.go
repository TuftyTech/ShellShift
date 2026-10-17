package publish

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	uuid = "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b"
	pbk  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	psk  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

func vmessURI(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return "vmess://" + strings.TrimRight(base64.StdEncoding.EncodeToString(raw), "=")
}
