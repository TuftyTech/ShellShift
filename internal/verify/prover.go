package verify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuftytech/shellshift/internal/tunnel"
)

// TunnelError marks a probe that failed before it reached the destination: the node itself
// could not carry the connection.
//
// The distinction decides whether hedging to another endpoint makes any sense. If gstatic
// refused us, cloudflare is worth trying. If the node's own outbound could not be dialed, every
// endpoint will fail identically — and trying them all is how one dead node became three dials
// and three times the load, which is the effect INV-53 exists to prevent and which the hedge
// loop was reintroducing on exactly the nodes that are most numerous.
type TunnelError struct{ Err error }

func (e *TunnelError) Error() string { return e.Err.Error() }
func (e *TunnelError) Unwrap() error { return e.Err }

// ProofResult is what a successful proof observed.
type ProofResult struct {
	// URL that answered first.
	URL string
	// Latency from request start to response headers.
	Latency time.Duration
}

// Prover decides whether a node actually carries traffic.
//
// The verdict is an HTTPS request whose certificate chain is verified, and that is a
// deliberate strengthening. The predecessor accepted an HTTP 204 fetched over plaintext,
// which a hostile node or a captive portal can forge trivially — and for nodes it had
// marked insecure it also ran the throughput leg with verification disabled, so even the
// HTTPS traffic proved nothing about the tunnel (INV-31).
//
// Verification here is of the *destination* certificate, terminated by this process at
// the far end of the tunnel. A node that intercepts gets a chain that does not validate,
// and fails.
type Prover struct {
	// URLs are raced against each other. Several providers are used so that one of them
	// blocking the verifier does not look like every node being dead.
	URLs []string
	// ExpectStatus is the status code that counts as proof.
	//
	// Measured, and worth recording because it looks like a place to loosen: over ~2,000 probed
	// nodes this check refused nothing. Every status in the failure counts — 403, 409, 429, 500,
	// 530 — came from sing-box's own HTTP handshake to the node on ws/httpupgrade/grpc, before
	// any request reached the destination. Relaxing the status would therefore admit no nodes and
	// weaken the verdict for nothing.
	ExpectStatus int
	// MaxBodyBytes caps what is read from the response. The proof endpoints answer with
	// an empty body; anything large is a captive portal.
	MaxBodyBytes int64

	// HedgeDelay is how long to wait for one probe before starting the next.
	//
	// Racing every endpoint at once buys the same latency as hedging and costs three times the
	// requests. That difference is not academic: a live run of 2,000 reachable nodes sent
	// roughly 6,000 requests to two providers in two minutes from one address, and they began
	// refusing — so working nodes failed with one shared reason and looked dead. Starting the
	// second probe only when the first has not answered keeps the latency win and sends one
	// request per node in the common case.
	HedgeDelay time.Duration

	// turn rotates which endpoint goes first.
	turn atomic.Int64

	// RootCAs overrides the trust anchors. It is nil in production, which means the
	// system roots. A test sets it to trust a local server; nothing in the normal path
	// can use it to weaken verification, because leaving it nil is the strict case.
	RootCAs *x509.CertPool
}

// NewProver returns the default configuration.
func NewProver() *Prover {
	return &Prover{
		URLs: []string{
			"https://www.gstatic.com/generate_204",
			"https://cp.cloudflare.com/generate_204",
			"https://connectivitycheck.gstatic.com/generate_204",
		},
		ExpectStatus: http.StatusNoContent,
		MaxBodyBytes: 4096,
		HedgeDelay:   900 * time.Millisecond,
	}
}

// Prove sends the configured probes with hedging and returns the first success.
//
// The predecessor tried two endpoints strictly in sequence, each with a seven-second timeout, so
// a dead node consumed fourteen seconds of a nineteen-second batch. Racing all of them fixes the
// latency and creates a different problem: three times the request volume against providers that
// then refuse us, which makes working nodes indistinguishable from dead ones (INV-39, INV-53).
//
// Hedging is the middle: the first probe goes out immediately, the next only if the first has not
// answered within HedgeDelay. Most nodes cost one request; a slow endpoint still cannot hold the
// whole verdict.
func (p *Prover) Prove(ctx context.Context, dialer tunnel.Dialer, target tunnel.Target) (ProofResult, error) {
	if len(p.URLs) == 0 {
		return ProofResult{}, fmt.Errorf("verify: no proof URLs configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		res ProofResult
		err error
	}
	results := make(chan outcome, len(p.URLs))
	// opened reports that some probe got its tunnel up. It is what arms the hedge: see below.
	opened := make(chan struct{}, len(p.URLs))

	var wg sync.WaitGroup
	launch := func(raw string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.probe(ctx, dialer, target, raw, opened)
			select {
			case results <- outcome{res, err}:
			case <-ctx.Done():
			}
		}()
	}

	// Probes are tried in a rotated order so the same endpoint is not always first across a
	// whole run: a fixed order concentrates the load the hedge is meant to spread.
	urls := p.rotated()
	launch(urls[0])
	next := 1

	var lastErr error
	pending := 1

	// The hedge is armed by the tunnel opening, not by the clock.
	//
	// A timer started here fires while the first probe is still trying to open the tunnel, and
	// then hedging sends a second probe down a tunnel that does not exist. That is the majority
	// case, not an edge case — most candidates in a public catalogue never carry traffic — and it
	// cost 2.2 dials per node measured on a 500-node sample.
	//
	// Waiting for the tunnel makes the two situations distinct: no tunnel means one dial and one
	// verdict, while a tunnel that opened and then went quiet is a slow *endpoint*, which is the
	// case hedging was introduced for (INV-53).
	hedge := time.NewTimer(time.Hour)
	hedge.Stop()
	defer hedge.Stop()
	armed := false

	for pending > 0 {
		select {
		case o := <-results:
			pending--
			if o.err == nil {
				return o.res, nil
			}
			lastErr = o.err
			// A node whose tunnel would not open fails every endpoint the same way, so there is
			// nothing to hedge to. Continuing cost three dials per dead node, and dead nodes are
			// the overwhelming majority: measured on a live run, 6,984 of 7,017 nodes that
			// reached the proof stage failed it. That is the request volume INV-53 identified as
			// making working nodes look dead, reintroduced through the retry path.
			var te *TunnelError
			if errors.As(o.err, &te) {
				pending = 0
				break
			}
			// An endpoint that refused us is a different matter: the next one is worth trying,
			// and immediately rather than after the hedge delay, since the slot is already free.
			if next < len(urls) {
				launch(urls[next])
				next++
				pending++
			}

		case <-opened:
			// The tunnel is up and the destination has not answered yet. From here a delay is
			// the endpoint's, so the hedge becomes worth arming.
			if !armed {
				armed = true
				hedge.Reset(p.hedgeDelay())
			}

		case <-hedge.C:
			if next < len(urls) {
				launch(urls[next])
				next++
				pending++
				hedge.Reset(p.hedgeDelay())
			}

		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			pending = 0
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return ProofResult{}, fmt.Errorf("no proof URL answered: %w", lastErr)
}

func (p *Prover) hedgeDelay() time.Duration {
	if p.HedgeDelay > 0 {
		return p.HedgeDelay
	}
	return 900 * time.Millisecond
}

// rotated returns the probe list with a rotating start, so load is spread across providers
// instead of landing on whichever one happens to be written first.
func (p *Prover) rotated() []string {
	n := len(p.URLs)
	if n < 2 {
		return p.URLs
	}
	start := int(p.turn.Add(1)-1) % n
	out := make([]string, 0, n)
	out = append(out, p.URLs[start:]...)
	out = append(out, p.URLs[:start]...)
	return out
}

// probe runs one proof request, reporting on opened — without blocking — the moment its tunnel is
// up. A nil channel means nobody is waiting on that signal.
func (p *Prover) probe(ctx context.Context, dialer tunnel.Dialer, target tunnel.Target,
	raw string, opened chan<- struct{}) (ProofResult, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ProofResult{}, fmt.Errorf("proof url %q: %w", raw, err)
	}
	port := uint16(443)
	if u.Port() != "" {
		n, perr := net.LookupPort("tcp", u.Port())
		if perr != nil {
			return ProofResult{}, fmt.Errorf("proof url %q: %w", raw, perr)
		}
		port = uint16(n)
	}
	host := u.Hostname()

	// Whether the tunnel ever opened. Recorded here because this is the only place that knows:
	// by the time the error surfaces from client.Do it reads the same as a destination failure.
	var dialed atomic.Bool

	transport := &http.Transport{
		DialContext: func(dctx context.Context, network, _ string) (net.Conn, error) {
			// The address argument is discarded on purpose: the destination is fixed by
			// the proof URL, and the route to it is the tunnel.
			conn, derr := dialer.DialContext(dctx, target, network, host, port)
			if derr != nil {
				return nil, derr
			}
			if dialed.CompareAndSwap(false, true) && opened != nil {
				// Buffered by the caller and reported once, so this never blocks the dial.
				select {
				case opened <- struct{}{}:
				default:
				}
			}
			return conn, nil
		},
		// Certificate verification of the destination. This is the whole proof: leaving
		// it off is what made the predecessor verdict forgeable (INV-31).
		TLSClientConfig: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    p.RootCAs,
		},
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   0, // governed by the context
		ResponseHeaderTimeout: 0,
		ForceAttemptHTTP2:     true,
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return ProofResult{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Transport: transport}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if !dialed.Load() {
			// The tunnel never opened, so this says nothing about the endpoint.
			return ProofResult{}, &TunnelError{Err: err}
		}
		return ProofResult{}, err
	}
	latency := time.Since(started)
	defer resp.Body.Close()

	// A captive portal answers with a page. Reading a bounded amount and then insisting
	// on the exact status is what tells the two apart.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, p.MaxBodyBytes))

	if resp.StatusCode != p.ExpectStatus {
		return ProofResult{}, fmt.Errorf("%s answered %d, want %d", host, resp.StatusCode, p.ExpectStatus)
	}
	return ProofResult{URL: raw, Latency: latency}, nil
}

// userAgent is a plain, honest identifier. The predecessor configured a browser
// user-agent it then never used, and its Go core hardcoded a different one.
const userAgent = "shellshift-verifier/1"
