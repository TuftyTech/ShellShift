package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/tunnel"
	"github.com/tuftytech/shellshift/internal/verify"
)

// runDoctor establishes the positive controls a diagnosis needs before it can blame the nodes.
//
// This exists because of a live run in which almost nothing passed. The plausible explanation —
// "the proof endpoints have started refusing us" — was wrong, and it took two minutes and two
// checks to know that: a direct request to each endpoint with no tunnel, and a run of the prover
// itself along a path known to work. Without them the plausible story would have been accepted
// as established and the real cause would have gone unlooked-for (INV-55).
//
// The controls answer, in order: does this machine have working egress at all, do the proof
// endpoints answer us right now, and does our own prover reach a verdict when the tunnel is not
// the variable. Only if all three pass does "the nodes are dead" become a claim about nodes.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "budget for each control")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := tunnel.CheckBuild(); err != nil {
		// Worth stating plainly rather than as a footnote: without the build tag every Reality
		// node fails to construct, which in the real corpus is 62% of the catalogue and looks
		// exactly like the feeds degrading (INV-49).
		return err
	}

	prover := verify.NewProver()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout*time.Duration(len(prover.URLs)+2))
	defer cancel()

	fmt.Printf("doctor: %d controls, %s each\n\n", 2, *timeout)

	direct := controlDirect(ctx, prover, *timeout)
	proverOK := controlProver(ctx, prover, *timeout)

	fmt.Println()
	switch {
	case !direct:
		fmt.Println("verdict: this machine cannot reach the proof endpoints without a tunnel.")
		fmt.Println("         Nothing can be concluded about any node until that is fixed.")
		return fmt.Errorf("the direct control failed")
	case !proverOK:
		fmt.Println("verdict: the endpoints answer directly, but the prover reaches no verdict")
		fmt.Println("         along a path known to work. The fault is ours, not the nodes'.")
		return fmt.Errorf("the prover control failed")
	default:
		fmt.Println("verdict: both controls pass. A run that proves nothing is a statement")
		fmt.Println("         about the nodes, not about this machine or this code.")
		return nil
	}
}

// controlDirect requests every proof endpoint with no tunnel in the way.
//
// A tunnel failure and a runner with no egress produce the same symptom — every node fails —
// and this is what tells them apart. Each endpoint is reported separately, because "one provider
// is refusing us" and "we have no network" are different problems with different fixes.
func controlDirect(ctx context.Context, p *verify.Prover, timeout time.Duration) bool {
	fmt.Println("control 1 — the proof endpoints, reached directly, no tunnel")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// nil in production, which is the strict case: the system roots. A test
				// points it at a local server, and nothing here can weaken verification
				// because there is no insecure option to set.
				RootCAs: p.RootCAs,
			},
			DisableKeepAlives: true,
		},
	}
	answered := 0
	for _, url := range p.URLs {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		status, err := head(reqCtx, client, url, p.MaxBodyBytes)
		cancel()
		elapsed := time.Since(started).Round(time.Millisecond)

		switch {
		case err != nil:
			fmt.Printf("  FAIL  %-52s %v\n", url, err)
		case status != p.ExpectStatus:
			fmt.Printf("  FAIL  %-52s status %d, want %d\n", url, status, p.ExpectStatus)
		default:
			fmt.Printf("  ok    %-52s %d in %s\n", url, status, elapsed)
			answered++
		}
	}
	fmt.Printf("        %d of %d endpoints answered\n", answered, len(p.URLs))
	// One endpoint is enough to prove egress works; the prover hedges across all of them.
	return answered > 0
}

// controlProver runs the real prover over a dialer that connects straight to the destination.
//
// The point is to remove the tunnel as a variable while keeping every other part of the
// verification path — the same prover, the same hedging, the same certificate verification. If
// this fails, no verdict about any node means anything, because the machinery producing verdicts
// is broken.
func controlProver(ctx context.Context, p *verify.Prover, timeout time.Duration) bool {
	fmt.Println("\ncontrol 2 — the prover itself, over a path known to work")

	// A node description that is never dialed as such: passthroughDialer ignores the target
	// and connects to the destination the prover asked for.
	node := model.Node{Identity: model.Identity{
		Protocol:  model.ProtoTrojan,
		Server:    "control.invalid",
		Port:      443,
		Transport: model.TransportTCP,
		Security:  model.SecurityTLS,
	}}

	proveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	res, err := p.Prove(proveCtx, passthroughDialer{}, tunnel.Target{Node: node})
	elapsed := time.Since(started).Round(time.Millisecond)

	if err != nil {
		fmt.Printf("  FAIL  the prover reached no verdict in %s: %v\n", elapsed, err)
		return false
	}
	fmt.Printf("  ok    proved via %s in %s (latency %s)\n",
		res.URL, elapsed, res.Latency.Round(time.Millisecond))
	return true
}

// passthroughDialer dials the destination directly, ignoring the node.
//
// It is the positive control's whole mechanism: the prover cannot tell it from a node that
// carries traffic perfectly, so a failure with this dialer is a failure in the prover.
type passthroughDialer struct{}

func (passthroughDialer) DialContext(ctx context.Context, _ tunnel.Target, network, host string,
	port uint16) (net.Conn, error) {

	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(port))))
}

func (passthroughDialer) Close() error { return nil }

// head requests a URL and returns its status, draining a bounded amount of body.
func head(ctx context.Context, client *http.Client, url string, maxBody int64) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Drained so the connection can be reused and a captive portal's body cannot be unbounded.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, nil
}
