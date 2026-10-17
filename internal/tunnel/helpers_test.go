package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func encodeVMess(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal vmess payload: %v", err)
	}
	return "vmess://" + strings.TrimRight(base64.StdEncoding.EncodeToString(raw), "=")
}
