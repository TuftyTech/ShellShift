package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// The predecessor logged url[:80] of a secret source list. Platform secret masking
// matches the exact value, so a truncated prefix reached a public log unmasked.
// SEC-029 requires that a prefix is scrubbed too.
func TestRedactsSecretAndItsPrefixes(t *testing.T) {
	const secret = "https://raw.example.com/private/list-of-sources.txt"

	cases := []struct {
		name string
		msg  string
	}{
		{"whole value", secret},
		{"truncated to 80", secret[:min(80, len(secret))]},
		{"truncated to 20", secret[:20]},
		{"embedded in a sentence", "fetching " + secret + " now"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := New(&buf, Options{Redact: []string{secret}})
			log.Info(tc.msg, slog.String("url", tc.msg))

			out := buf.String()
			if strings.Contains(out, secret[:RedactMinPrefix]) {
				t.Fatalf("secret prefix leaked into output: %q", out)
			}
			if !strings.Contains(out, redacted) {
				t.Fatalf("expected a redaction marker, got: %q", out)
			}
		})
	}
}

func TestShortValuesAreNotTreatedAsSecrets(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, Options{Redact: []string{"abc"}})
	log.Info("value abc stays")

	if strings.Contains(buf.String(), redacted) {
		t.Fatalf("a %d-character value must not trigger redaction: %q", 3, buf.String())
	}
}

func TestImportPerformsNoIO(t *testing.T) {
	// New writes only to the writer it is given. Constructing a logger must not
	// create files or directories the way the predecessor did at import time.
	var buf bytes.Buffer
	log := New(&buf, Options{Format: FormatJSON, Level: slog.LevelDebug})
	log.Debug("hello")
	if buf.Len() == 0 {
		t.Fatal("expected the provided writer to receive the record")
	}
}
