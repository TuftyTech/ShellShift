package obs

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Format selects the encoding of log records.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Options configures a logger. The zero value is valid and yields text output at
// info level.
type Options struct {
	Format Format
	Level  slog.Level
	// Redact holds values that must never appear in output. Each occurrence is
	// replaced wholesale, and any prefix of length RedactMinPrefix or longer is
	// replaced too — truncating a secret is what defeats GitHub Actions masking.
	Redact []string
}

// RedactMinPrefix is the shortest prefix of a secret that is still treated as
// disclosure. The predecessor logged url[:80] of a secret source list, which the
// platform masker did not catch because it matches only the exact value.
const RedactMinPrefix = 12

// New builds a logger writing to w. It performs no I/O of its own: opening files,
// creating directories, and installing a process-wide default are the caller's
// decisions, made explicitly.
func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: opts.Level}

	var h slog.Handler
	switch opts.Format {
	case FormatJSON:
		h = slog.NewJSONHandler(w, handlerOpts)
	default:
		h = slog.NewTextHandler(w, handlerOpts)
	}

	if len(opts.Redact) > 0 {
		h = &redactingHandler{inner: h, secrets: compileSecrets(opts.Redact)}
	}
	return slog.New(h)
}

func compileSecrets(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) >= RedactMinPrefix {
			out = append(out, v)
		}
	}
	return out
}

// redactingHandler scrubs known secrets from every string attribute and from the
// message itself before the record reaches the underlying handler.
type redactingHandler struct {
	inner   slog.Handler
	secrets []string
}

const redacted = "[REDACTED]"

func (h *redactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, h.scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = h.scrubAttr(a)
	}
	return &redactingHandler{inner: h.inner.WithAttrs(scrubbed), secrets: h.secrets}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: h.inner.WithGroup(name), secrets: h.secrets}
}

func (h *redactingHandler) scrubAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		return slog.String(a.Key, h.scrub(a.Value.String()))
	}
	return a
}

// scrub replaces every secret and every sufficiently long prefix of a secret.
func (h *redactingHandler) scrub(s string) string {
	for _, secret := range h.secrets {
		if strings.Contains(s, secret) {
			s = strings.ReplaceAll(s, secret, redacted)
			continue
		}
		for n := len(secret) - 1; n >= RedactMinPrefix; n-- {
			prefix := secret[:n]
			if strings.Contains(s, prefix) {
				s = strings.ReplaceAll(s, prefix, redacted)
				break
			}
		}
	}
	return s
}
