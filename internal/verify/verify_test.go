package verify

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/policy"
	"github.com/tuftytech/shellshift/internal/tunnel"
)

// directDialer stands in for a working proxy: it connects straight to the destination,
// which is what a node that genuinely carries traffic looks like from the prover.
type directDialer struct{ redirectTo string }

func (d directDialer) DialContext(ctx context.Context, _ tunnel.Target, network, host string, port uint16) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if d.redirectTo != "" {
		target = d.redirectTo
	}
	var dl net.Dialer
	return dl.DialContext(ctx, network, target)
}

func (d directDialer) Close() error { return nil }

// refusingDialer is a node that cannot carry a connection at all, counting the attempts.
type refusingDialer struct{ n *atomic.Int64 }

func (d refusingDialer) DialContext(context.Context, tunnel.Target, string, string, uint16) (net.Conn, error) {
	d.n.Add(1)
	return nil, errors.New("dial: connection refused")
}
func (refusingDialer) Close() error { return nil }

// slowDialer opens the tunnel, but only after a delay: the case a clock-armed hedge mistook for
// a slow endpoint.
type slowDialer struct {
	delay time.Duration
	n     *atomic.Int64
	to    string
}

func (d slowDialer) DialContext(ctx context.Context, _ tunnel.Target, network, _ string, _ uint16) (net.Conn, error) {
	d.n.Add(1)
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var dl net.Dialer
	return dl.DialContext(ctx, network, d.to)
}
func (slowDialer) Close() error { return nil }

func testNode() model.Node {
	return model.Node{Identity: model.Identity{
		Protocol: model.ProtoTrojan,
		// A hostname rather than a literal: a literal address is vetted directly by the
		// resolver and 127.0.0.1 is denied, which is correct behaviour and covered by its own
		// test — but it means a test node written that way never reaches the tunnel.
		Server:     "node.example.com",
		Port:       443,
		Credential: "p4ss",
		Transport:  model.TransportTCP,
		Security:   model.SecurityTLS,
	}}
}

func poolFor(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// The happy path: an HTTPS endpoint with a chain the prover can verify, answering the
// expected status.
func TestProofSucceedsOnVerifiedHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewProver()
	p.URLs = []string{srv.URL + "/generate_204"}
	p.RootCAs = poolFor(t, srv)

	res, err := p.Prove(context.Background(), directDialer{}, tunnel.Target{
		Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
	})
	if err != nil {
		t.Fatalf("proof failed: %v", err)
	}
	if res.Latency <= 0 {
		t.Fatal("latency was not measured")
	}
}

// INV-31, the central change. A node that intercepts the connection presents a chain the
// prover cannot verify, and must fail. The predecessor accepted a plaintext 204, which
// any interceptor can answer, so this scenario passed there.
func TestProofFailsWhenTheChainDoesNotVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewProver()
	p.URLs = []string{srv.URL + "/generate_204"}
	// RootCAs left nil: the system roots do not trust this server, exactly as they would
	// not trust an interceptor.

	_, err := p.Prove(context.Background(), directDialer{}, tunnel.Target{
		Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
	})
	if err == nil {
		t.Fatal("a certificate that does not verify must not count as proof")
	}
}

// A captive portal answers with a page and a 200. Insisting on the exact status is what
// tells it apart from a working tunnel.
func TestProofFailsOnCaptivePortalResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>please log in</html>"))
	}))
	defer srv.Close()

	p := NewProver()
	p.URLs = []string{srv.URL + "/generate_204"}
	p.RootCAs = poolFor(t, srv)

	if _, err := p.Prove(context.Background(), directDialer{}, tunnel.Target{
		Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
	}); err == nil {
		t.Fatal("a 200 with a body must not count as proof")
	}
}

// INV-53. Hedging, not racing and not sequence.
//
// Sequence was the predecessor mistake: two endpoints one after the other at seven seconds each
// meant a dead node cost fourteen. Racing all of them fixes the latency and triples the request
// volume, which on a live run of two thousand reachable nodes made the providers refuse us and
// working nodes look dead. This test pins both halves: a slow first endpoint must not hold the
// verdict, and a fast first endpoint must not cause a second request at all.
func TestProbesAreHedgedNotRacedOrSequential(t *testing.T) {
	t.Run("a slow endpoint does not hold the verdict", func(t *testing.T) {
		slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			}
		}))
		defer slow.Close()
		fast := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer fast.Close()

		pool := x509.NewCertPool()
		pool.AddCert(slow.Certificate())
		pool.AddCert(fast.Certificate())

		p := NewProver()
		p.URLs = []string{slow.URL + "/generate_204", fast.URL + "/generate_204"}
		p.RootCAs = pool
		p.HedgeDelay = 200 * time.Millisecond

		started := time.Now()
		res, err := p.Prove(context.Background(), directDialer{}, tunnel.Target{
			Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
		})
		elapsed := time.Since(started)
		if err != nil {
			t.Fatalf("proof failed: %v", err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("took %v: the hedge did not fire", elapsed)
		}
		if res.URL != fast.URL+"/generate_204" {
			t.Fatalf("the fast endpoint should have answered, got %q", res.URL)
		}
	})

	t.Run("a fast first endpoint costs one request", func(t *testing.T) {
		var first, second atomic.Int64
		a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			first.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer a.Close()
		b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			second.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer b.Close()

		pool := x509.NewCertPool()
		pool.AddCert(a.Certificate())
		pool.AddCert(b.Certificate())

		p := NewProver()
		p.URLs = []string{a.URL + "/generate_204", b.URL + "/generate_204"}
		p.RootCAs = pool
		p.HedgeDelay = 2 * time.Second

		if _, err := p.Prove(context.Background(), directDialer{}, tunnel.Target{
			Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
		}); err != nil {
			t.Fatalf("proof failed: %v", err)
		}
		if total := first.Load() + second.Load(); total != 1 {
			t.Fatalf("sent %d requests for one node, want 1: hedging must not fan out when the "+
				"first endpoint answers", total)
		}
	})

	// INV-53, the case the hedge loop was getting wrong. A node that cannot carry a connection
	// fails every endpoint identically, so hedging to the others is pure load — and dead nodes
	// are the overwhelming majority of a public catalogue, so this is the common path, not an
	// edge case. Measured before the fix: 2.2 tunnel dials per node against 1.19 after.
	t.Run("a node that cannot dial costs one attempt, not one per endpoint", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		p := NewProver()
		// Three endpoints, so a fan-out would be visible as three dials.
		p.URLs = []string{
			srv.URL + "/generate_204", srv.URL + "/generate_204", srv.URL + "/generate_204",
		}
		p.RootCAs = poolFor(t, srv)
		p.HedgeDelay = 50 * time.Millisecond

		var dials atomic.Int64
		if _, err := p.Prove(context.Background(), refusingDialer{n: &dials}, tunnel.Target{
			Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
		}); err == nil {
			t.Fatal("a node whose tunnel cannot open must not be proven")
		}
		if got := dials.Load(); got != 1 {
			t.Fatalf("dialed the tunnel %d times for a node that cannot dial, want 1", got)
		}
		if hits.Load() != 0 {
			t.Fatalf("sent %d requests to the endpoint for an undialable node, want 0", hits.Load())
		}
	})

	// The hedge is armed by the tunnel opening rather than by the clock. A timer started at the
	// request fires while the first probe is still dialing, which is how a node with no tunnel
	// ended up sending a probe to every endpoint.
	t.Run("a slow tunnel does not arm the hedge", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		p := NewProver()
		p.URLs = []string{
			srv.URL + "/generate_204", srv.URL + "/generate_204", srv.URL + "/generate_204",
		}
		p.RootCAs = poolFor(t, srv)
		// Far shorter than the dial below, so a clock-armed hedge would fire twice.
		p.HedgeDelay = 100 * time.Millisecond

		var dials atomic.Int64
		_, err := p.Prove(context.Background(), slowDialer{
			delay: 600 * time.Millisecond, n: &dials, to: srv.Listener.Addr().String(),
		}, tunnel.Target{Node: testNode(), Server: netip.MustParseAddr("127.0.0.1")})
		if err != nil {
			t.Fatalf("proof failed: %v", err)
		}
		// One dial, one request: the delay was the tunnel's, and hedging cannot help with that.
		if got := dials.Load(); got != 1 {
			t.Fatalf("dialed %d times while the tunnel was slow to open, want 1", got)
		}
		if hits.Load() != 1 {
			t.Fatalf("sent %d requests, want 1", hits.Load())
		}
	})

	t.Run("a failing endpoint frees the slot immediately", func(t *testing.T) {
		bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer bad.Close()
		good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer good.Close()

		pool := x509.NewCertPool()
		pool.AddCert(bad.Certificate())
		pool.AddCert(good.Certificate())

		p := NewProver()
		p.URLs = []string{bad.URL + "/generate_204", good.URL + "/generate_204"}
		p.RootCAs = pool
		// A long hedge delay: if the failure did not free the slot, this would time out.
		p.HedgeDelay = 30 * time.Second

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := p.Prove(ctx, directDialer{}, tunnel.Target{
			Node: testNode(), Server: netip.MustParseAddr("127.0.0.1"),
		}); err != nil {
			t.Fatalf("a failed probe must free the slot at once: %v", err)
		}
	})
}

// --- engine-level tests -------------------------------------------------------

// The stage ledger records what happened at each step separately. The predecessor added
// translation rejects, reachability failures and end-to-end losses into one number that
// the dashboard labelled as reachability, and its tuning decisions rested on it (INV-41).
func TestStagesAreRecordedSeparately(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewProver()
	p.URLs = []string{srv.URL + "/generate_204"}
	p.RootCAs = poolFor(t, srv)

	e := New(directDialer{}, p)
	e.Resolver = &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}
	e.SkipReach = true

	node := testNode()
	node.Identity.Server = "node.example.com"

	v := e.Verify(context.Background(), node)
	if !v.Proven {
		stage, reason := v.FailedAt()
		t.Fatalf("expected proof, failed at %s: %s", stage, reason)
	}
	for _, want := range []model.Stage{model.StagePolicy, model.StageProof} {
		if outcome, ok := v.Pass(want); !ok || outcome != model.OutcomePass {
			t.Fatalf("stage %s: outcome=%q recorded=%v", want, outcome, ok)
		}
	}
	if v.Measured.Latency <= 0 {
		t.Fatal("latency should be recorded on the verdict")
	}
}

// A host that resolves only into denied space never reaches the tunnel, and the refusal
// is attributed to policy rather than to the node being unreachable.
func TestPolicyFailureShortCircuits(t *testing.T) {
	e := New(directDialer{}, NewProver())
	e.Resolver = &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}}

	node := testNode()
	node.Identity.Server = "metadata.example.com"

	v := e.Verify(context.Background(), node)
	if v.Proven {
		t.Fatal("a node resolving to the metadata address must not be proven")
	}
	stage, _ := v.FailedAt()
	if stage != model.StagePolicy {
		t.Fatalf("failed at %s, want %s", stage, model.StagePolicy)
	}
	if _, ok := v.Pass(model.StageProof); ok {
		t.Fatal("the proof stage must not run after a policy refusal")
	}
}

// INV-39. A dead node must cost a bounded amount of time, and the bound is the total budget
// rather than the sum of the stage budgets.
//
// The predecessor's rule was that the probe timeout is max_latency + 2000 and no more, for the
// stated reason that "a larger timeout only makes dead nodes hang longer". ShellShift keeps the
// principle in a different mechanism: every stage is bounded and the whole node is bounded
// again on top, so a node that never answers cannot consume the run.
func TestADeadNodeIsBoundedByTheTotalBudget(t *testing.T) {
	// A listener that accepts and then says nothing at all: the worst case for any timeout,
	// because nothing ever fails fast.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	go func() {
		for {
			conn, aerr := silent.Accept()
			if aerr != nil {
				return
			}
			// Hold it open without writing. Closing would let the client fail early.
			defer conn.Close()
		}
	}()

	e := New(directDialer{redirectTo: silent.Addr().String()}, NewProver())
	e.SkipReach = true
	e.Resolver = fixedResolver("93.184.216.34")
	e.Budget = Budget{
		Resolve:    200 * time.Millisecond,
		Reach:      200 * time.Millisecond,
		Proof:      5 * time.Second, // deliberately larger than Total
		Throughput: 5 * time.Second,
		Total:      600 * time.Millisecond,
	}

	started := time.Now()
	v := e.Verify(context.Background(), testNode())
	elapsed := time.Since(started)

	if v.Proven {
		t.Fatal("a node that never answers must not be proven")
	}
	// The ceiling is what is being asserted. The margin absorbs scheduling noise without
	// letting a regression to "sum of the stage budgets" pass: that would be seconds.
	if elapsed > e.Budget.Total+1500*time.Millisecond {
		t.Fatalf("a dead node cost %v against a total budget of %v", elapsed, e.Budget.Total)
	}
	if stage, _ := v.FailedAt(); stage == "" {
		t.Fatal("the verdict must name the stage that ran out of time")
	}
}

// INV-53. The proof stage is bounded separately from the verification stage, because it is the
// only stage that touches shared third parties.
//
// One limit cannot serve both: reach dials a distinct node per candidate and wants thousands in
// flight at 100k candidates, while proof points every one of those at three endpoints. This test
// pins that a wide verification concurrency does not become a wide request rate.
func TestProofsAreBoundedSeparatelyFromVerifications(t *testing.T) {
	var inFlight, peak atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		// Held long enough that concurrent arrivals overlap observably.
		time.Sleep(120 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	const limit = 3
	prover := NewProver()
	prover.URLs = []string{srv.URL + "/generate_204"}
	prover.RootCAs = poolFor(t, srv)

	e := New(directDialer{}, prover)
	e.SkipReach = true
	e.Resolver = fixedResolver("93.184.216.34")
	e.LimitProofs(limit)

	// Forty nodes verified with no bound of their own: the only thing holding the request rate
	// down is the proof limit.
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Verify(context.Background(), testNode())
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > limit {
		t.Fatalf("%d proofs were in flight at once against a limit of %d", got, limit)
	}
	if peak.Load() < 2 {
		t.Fatalf("peak concurrency was %d: the test did not actually overlap, so it proves "+
			"nothing about the bound", peak.Load())
	}
}

// A UDP protocol has no TCP handshake to probe, so the stage is skipped explicitly. The
// predecessor returned early from the entire check for these, which also skipped address
// vetting (INV-33).
func TestUDPProtocolSkipsReachButNotPolicy(t *testing.T) {
	e := New(directDialer{}, NewProver())
	e.Resolver = &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}
	e.Prover = &Prover{URLs: []string{"https://127.0.0.1:1/generate_204"}, ExpectStatus: 204}

	node := testNode()
	node.Identity.Protocol = model.ProtoHysteria2
	node.Identity.Server = "hy2.example.com"

	v := e.Verify(context.Background(), node)

	outcome, ok := v.Pass(model.StageReach)
	if !ok {
		t.Fatal("the reach stage must be recorded even when skipped")
	}
	if outcome != model.OutcomeSkipped {
		t.Fatalf("reach outcome = %q, want %q", outcome, model.OutcomeSkipped)
	}
	if pol, ok := v.Pass(model.StagePolicy); !ok || pol != model.OutcomePass {
		t.Fatal("policy must still have run for a UDP protocol")
	}
}

// fixedResolver answers every lookup with one address.
func fixedResolver(addr string) *policy.Resolver {
	return &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(addr)}, nil
	}}
}
