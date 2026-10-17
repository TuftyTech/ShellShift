package intake

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleFeed = "vless://b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b@example.com:443?security=tls\n" +
	"trojan://p4ss@example.com:8443?security=tls\n"

// SEC-004. A feed served over plaintext can be rewritten by anyone on the path, and the
// whole product rests on what those feeds contain.
func TestOnlyHTTPSIsAllowed(t *testing.T) {
	f := NewFetcher(DefaultLimits())
	for _, u := range []string{
		"http://example.com/list.txt",
		"ftp://example.com/list.txt",
		"file:///etc/passwd",
		"example.com/list.txt",
	} {
		t.Run(u, func(t *testing.T) {
			if _, err := f.Fetch(context.Background(), u); err == nil {
				t.Fatalf("%s was allowed", u)
			}
		})
	}
}

// SEC-003. The body cap refuses rather than truncates: a half-read feed parses into a
// plausible but arbitrary subset, and the run would look successful.
func TestBodyCapRefusesInsteadOfTruncating(t *testing.T) {
	big := strings.Repeat("x", 4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 64; i++ {
			_, _ = w.Write([]byte(big))
		}
	}))
	defer srv.Close()

	limits := DefaultLimits()
	limits.MaxBytes = 8 << 10
	f := NewFetcher(limits)
	f.Client = srv.Client()

	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("an oversized body must be refused")
	}
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want a limit error", err)
	}
}

// A declared length over the cap is refused before a byte is read.
func TestDeclaredLengthOverCapIsRefusedEarly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "999999999")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	limits := DefaultLimits()
	limits.MaxBytes = 1024
	f := NewFetcher(limits)
	f.Client = srv.Client()

	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want a limit error", err)
	}
}

// The bound the predecessor lacked entirely. A small response can expand without limit,
// which is exactly what a compression bomb is.
func TestDecompressedSizeIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		chunk := strings.Repeat("A", 64<<10)
		for i := 0; i < 64; i++ {
			_, _ = gz.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	limits := DefaultLimits()
	limits.MaxDecodedBytes = 128 << 10
	f := NewFetcher(limits)
	f.Client = srv.Client()

	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want a limit error on the decompressed stream", err)
	}
}

func TestPlainFeedIsRead(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sampleFeed))
	}))
	defer srv.Close()

	f := NewFetcher(DefaultLimits())
	f.Client = srv.Client()

	body, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(body.Lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(body.Lines))
	}
	if body.Digest == "" {
		t.Fatal("digest must be computed so mirrored feeds can be skipped")
	}
	if body.Base64Wrapped {
		t.Fatal("a plain feed must not be reported as base64 wrapped")
	}
}

// INV-24 and the whole-feed base64 convention.
func TestBase64WrappedFeedIsUnwrapped(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte(sampleFeed))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(wrapped))
	}))
	defer srv.Close()

	f := NewFetcher(DefaultLimits())
	f.Client = srv.Client()

	body, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !body.Base64Wrapped {
		t.Fatal("the feed should have been reported as base64 wrapped")
	}
	if len(body.Lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(body.Lines))
	}
}

// The conservative ordering matters: a feed that already contains links is never decoded,
// so an unrelated base64 payload inside it cannot mangle the feed.
func TestFeedContainingLinksIsNeverDecoded(t *testing.T) {
	mixed := sampleFeed + base64.StdEncoding.EncodeToString([]byte("unrelated payload")) + "\n"
	out, wrapped := unwrapBase64Feed(mixed)
	if wrapped {
		t.Fatal("a feed containing links must not be treated as base64")
	}
	if out != mixed {
		t.Fatal("the feed was altered")
	}
}

func TestLineCapIsEnforced(t *testing.T) {
	_, _, err := splitLines("vless://"+strings.Repeat("a", 9000), 8<<10)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want a limit error", err)
	}
}

func TestBlankLinesAndWhitespaceAreDropped(t *testing.T) {
	lines, _, err := splitLines("  a  \r\n\r\n\tb\t\n\n", 1024)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(lines) != 2 || lines[0] != "a" || lines[1] != "b" {
		t.Fatalf("got %q", lines)
	}
}

// A profile header is not a candidate node. Counting formatting as offered nodes makes the
// collected figure a measure of file layout rather than of what a feed actually offered —
// and that figure is the first stage of the published funnel.
func TestCommentLinesAreDroppedAndCounted(t *testing.T) {
	feed := "#profile-title: something\n" +
		"// a note\n" +
		"vless://b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b@example.com:443?security=tls\n"
	lines, comments, err := splitLines(feed, 8<<10)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("candidate lines = %d, want 1: %q", len(lines), lines)
	}
	if comments != 2 {
		t.Fatalf("comments = %d, want 2", comments)
	}
}

// A real feed in the live corpus is 99.8 MiB across 420,430 lines and historically produced
// 197 working nodes. Under a byte cap it was refused outright; with no cap at all — which is
// what the predecessor did — it is an out-of-memory vector reachable by anyone who publishes
// a feed. A bounded prefix keeps it usable and the memory bounded.
func TestHugeFeedIsTruncatedNotRefused(t *testing.T) {
	line := "vless://b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b@example.com:443?security=tls\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 5000; i++ {
			_, _ = w.Write([]byte(line))
		}
	}))
	defer srv.Close()

	limits := DefaultLimits()
	limits.MaxNodesPerSource = 100
	f := NewFetcher(limits)
	f.Client = srv.Client()

	body, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("a large feed must be truncated, not refused: %v", err)
	}
	if len(body.Lines) != limits.MaxNodesPerSource {
		t.Fatalf("got %d candidates, want the cap of %d", len(body.Lines), limits.MaxNodesPerSource)
	}
	if !body.Truncated {
		t.Fatal("truncation must be reported: a silently shortened feed looks like a smaller feed")
	}
}

// The byte cap still applies, because it is what stops the transfer itself from being
// unbounded.
func TestByteCapStillAppliesWhileStreaming(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("x", 4096)
		for i := 0; i < 64; i++ {
			_, _ = w.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	limits := DefaultLimits()
	limits.MaxBytes = 8 << 10
	f := NewFetcher(limits)
	f.Client = srv.Client()

	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want a limit error", err)
	}
}
