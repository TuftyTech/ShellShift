package intake

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/tuftytech/shellshift/internal/policy"
)

// Fetcher retrieves source feeds.
//
// Every outbound connection it makes is vetted by the same egress guard that protects the
// verification path. Source URLs are attacker-influenced too — they are configuration,
// but configuration assembled from public lists — so an entry pointing at an internal
// address must be refused here as well, not only when dialing a node (SEC-004).
type Fetcher struct {
	Limits Limits
	Client *http.Client
	// UserAgent identifies the collector honestly. The predecessor configured a browser
	// user-agent in a block of settings that nothing ever read, and then sent no
	// user-agent at all.
	UserAgent string
}

// NewFetcher builds a fetcher whose transport refuses to connect to anything the egress
// guard denies, and which follows a bounded number of redirects.
func NewFetcher(limits Limits) *Fetcher {
	transport := &http.Transport{
		DialContext:           guardedDial,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		// Compression is handled explicitly so the decompressed size can be bounded.
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= limits.MaxRedirects {
				return fmt.Errorf("intake: more than %d redirects", limits.MaxRedirects)
			}
			// Each hop is checked again: a redirect is a fresh destination.
			return checkScheme(req.URL.Scheme)
		},
	}
	return &Fetcher{Limits: limits, Client: client, UserAgent: "shellshift-collector/1"}
}

// Body is a fetched feed.
type Body struct {
	// Lines are the feed contents, already split and size-checked.
	Lines []string
	// Digest is the SHA-256 of the raw body, used to skip feeds that mirror each other
	// byte for byte (INV-24).
	Digest string
	// Bytes is the size of the raw body.
	Bytes int64
	// Base64Wrapped records that the whole feed was base64 and had to be unwrapped.
	Base64Wrapped bool
	// Comments counts the non-candidate lines that were dropped, so the information is
	// not simply lost.
	Comments int
	// Truncated records that the candidate cap was reached and the rest of the feed was
	// not read. It is reported rather than hidden: a silently shortened feed looks exactly
	// like a feed that got smaller.
	Truncated bool
}

// Fetch retrieves one source.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (Body, error) {
	if err := checkScheme(schemeOf(rawURL)); err != nil {
		return Body{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, f.Limits.PerSource)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Body{}, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := f.Client.Do(req)
	if err != nil {
		return Body{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Body{}, fmt.Errorf("intake: status %d", resp.StatusCode)
	}
	// A declared length over the cap is refused before a single byte is read.
	if resp.ContentLength > 0 && resp.ContentLength > f.Limits.MaxBytes {
		return Body{}, fmt.Errorf("%w: declared %d bytes", ErrLimitExceeded, resp.ContentLength)
	}

	hasher := sha256.New()
	wire := newLimitedReader(io.TeeReader(resp.Body, hasher), f.Limits.MaxBytes, "body")

	var reader io.Reader = wire
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, gerr := gzip.NewReader(wire)
		if gerr != nil {
			return Body{}, fmt.Errorf("intake: gzip: %w", gerr)
		}
		defer gz.Close()
		// The decompressed stream gets its own allowance: this is the bound the
		// predecessor lacked entirely, and it is what a compression bomb attacks.
		reader = newLimitedReader(gz, f.Limits.MaxDecodedBytes, "decompressed body")
	}

	// Streaming with a candidate cap rather than reading the whole body.
	//
	// This is not a micro-optimisation. A real feed in the live corpus is 99.8 MiB across
	// 420,430 lines and historically produced 197 working nodes: the worst yield per byte
	// of anything measured. Under a byte cap it was refused outright, losing those nodes;
	// with no cap at all — which is what the predecessor did — it is an out-of-memory
	// vector reachable by anyone who publishes a feed. Taking a bounded prefix keeps the
	// feed usable and the memory bounded, and the truncation is reported rather than
	// hidden.
	body, err := readFeed(reader, f.Limits)
	if err != nil {
		return Body{}, err
	}
	body.Digest = hex.EncodeToString(hasher.Sum(nil))
	return body, nil
}

func schemeOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i > 0 {
		return strings.ToLower(rawURL[:i])
	}
	return ""
}

// checkScheme allows only HTTPS. A feed served over plaintext can be rewritten in
// transit by anyone on the path, and the whole product rests on the contents of these
// feeds (SEC-004).
func checkScheme(scheme string) error {
	if strings.ToLower(scheme) != "https" {
		return fmt.Errorf("intake: scheme %q is not allowed, only https", scheme)
	}
	return nil
}

// guardedDial resolves and vets before connecting, so a source URL cannot reach inward.
func guardedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	r := policy.NewResolver()
	addr, err := r.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}

var _ = netip.Addr{}
