package verify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tuftytech/shellshift/internal/tunnel"
)

// Meter measures how fast a node carries bytes.
//
// Every constant here is carried over from the predecessor with its reason intact, because
// each one was paid for (INV-35, INV-36):
//
//   - The clock starts after the response headers arrive. Including the handshake and
//     time-to-first-byte systematically understated fast nodes with high latency, and while
//     speed was still a filter it was throwing away good ones.
//   - A sample below the validity floor is rejected rather than believed. A stalled transfer
//     otherwise reports a near-zero figure, and a near-zero figure published as a measurement
//     reads as a slow node.
//   - The result is clamped. A figure above the clamp is a measurement artefact, not a node.
type Meter struct {
	// URL is the download endpoint. The size is a query parameter on the provider this
	// project uses, so the target byte count and the URL are related but not the same thing.
	URL string
	// TargetBytes is how much to ask for.
	TargetBytes int64
	// MinValidBytes is the floor below which a sample is not representative.
	MinValidBytes int64
	// Clamp bounds the reported figure.
	Clamp float64
	// EarlyAbortAfter and EarlyAbortBelow together stop a transfer that is clearly going
	// nowhere, rather than waiting out the whole budget for a number that will be discarded.
	EarlyAbortAfter time.Duration
	EarlyAbortBelow int64
	// RootCAs overrides trust anchors for tests; nil means the system roots.
	RootCAs *x509.CertPool
}

// NewMeter returns the default configuration.
func NewMeter() *Meter {
	return &Meter{
		URL:             "https://speed.cloudflare.com/__down?bytes=524288",
		TargetBytes:     512 << 10,
		MinValidBytes:   256 << 10,
		Clamp:           3000,
		EarlyAbortAfter: 3500 * time.Millisecond,
		EarlyAbortBelow: 64 << 10,
	}
}

// Measure downloads through the node and reports throughput in megabits per second.
//
// A failure is not fatal to the node: surviving the proof is what keeps it, and throughput is
// a ranking signal (INV-37). The caller records a zero and moves on rather than dropping a
// working node over a measurement.
func (m *Meter) Measure(ctx context.Context, dialer tunnel.Dialer, target tunnel.Target) (mbps float64, bytes int64, err error) {
	u, err := url.Parse(m.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("throughput: %w", err)
	}
	host := u.Hostname()
	port := uint16(443)
	if u.Port() != "" {
		n, perr := net.LookupPort("tcp", u.Port())
		if perr != nil {
			return 0, 0, fmt.Errorf("throughput: %w", perr)
		}
		port = uint16(n)
	}

	transport := &http.Transport{
		DialContext: func(dctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dctx, target, network, host, port)
		},
		TLSClientConfig: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    m.RootCAs,
		},
		DisableKeepAlives:  true,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("throughput: status %d", resp.StatusCode)
	}

	// The clock starts here, after the headers. This is the whole reason the predecessor
	// figure was wrong for fast, distant nodes.
	started := time.Now()

	buf := make([]byte, 32<<10)
	var total int64
	for total < m.TargetBytes {
		n, rerr := resp.Body.Read(buf)
		total += int64(n)

		if elapsed := time.Since(started); elapsed > m.EarlyAbortAfter && total < m.EarlyAbortBelow {
			return 0, total, fmt.Errorf("throughput: %d bytes in %v, abandoning", total, elapsed.Round(time.Millisecond))
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return 0, total, rerr
		}
	}
	elapsed := time.Since(started)

	if total < m.MinValidBytes {
		// Too truncated to be representative. Reporting it would publish a stalled transfer
		// as a slow node.
		return 0, total, fmt.Errorf("throughput: only %d bytes, floor is %d", total, m.MinValidBytes)
	}

	// A floor on elapsed time keeps a very fast local response from dividing by almost zero.
	if elapsed < 50*time.Millisecond {
		elapsed = 50 * time.Millisecond
	}
	mbps = float64(total) * 8 / (elapsed.Seconds() * 1_000_000)
	if mbps > m.Clamp {
		mbps = m.Clamp
	}
	return mbps, total, nil
}
