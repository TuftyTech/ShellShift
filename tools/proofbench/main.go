// Command proofbench answers why a run proves so few nodes.
//
// A live run reached 7,017 nodes over TCP and proved 33 of them. That ratio is either a fact
// about public proxies or a fact about our settings, and the published telemetry cannot tell
// which: every proof failure lands in one bucket, "no proof endpoint answered", because Prove
// returns only the last error and summariseReason collapses the rest.
//
// So this runs the same sample of nodes under several settings and reports the raw error
// distribution. It is a diagnostic, not a gate: it makes real requests to real third parties and
// is meant to be run by hand while tuning, which is why it is in tools/ rather than in the
// binary. INV-55 is the rule it serves — a diagnosis needs a positive control and real numbers,
// not a plausible story.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/intake"
	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/pipeline"
	"github.com/tuftytech/shellshift/internal/policy"
	"github.com/tuftytech/shellshift/internal/tunnel"
	"github.com/tuftytech/shellshift/internal/verify"
)

// arm is one setting under test.
type arm struct {
	name        string
	concurrency int
	proof       time.Duration
	reach       time.Duration
	hedge       time.Duration
	urls        []string
	skipReach   bool
}

// broadEndpoints spreads the load across operators instead of two.
//
// The default list is three URLs of which two are Google, so a run sends two thirds of its proof
// traffic to one operator. Every entry here answers 204 to an unauthenticated GET and is a
// published connectivity-check endpoint of a different organisation.
var broadEndpoints = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
	"https://connectivitycheck.gstatic.com/generate_204",
	"https://www.google.com/generate_204",
	"https://edge.microsoft.com/captiveportal/generate_204",
	"https://detectportal.firefox.com/success.txt",
	"https://captive.apple.com/hotspot-detect.html",
	"https://connectivity-check.ubuntu.com",
}

func main() {
	feed := flag.String("feed", "", "feed URL to sample from (required)")
	sample := flag.Int("sample", 300, "how many decoded nodes to test per arm")
	only := flag.String("only", "", "run only the arms whose names contain this substring")
	raw := flag.Bool("raw", false, "print every proof error verbatim instead of bucketing it")
	byT := flag.Bool("by-transport", false, "key the failure buckets by transport, to see which transports fail how")
	flag.Parse()
	rawErrors = *raw
	byTransport = *byT

	if *feed == "" {
		fmt.Fprintln(os.Stderr, "proofbench: -feed is required")
		os.Exit(2)
	}
	if err := tunnel.CheckBuild(); err != nil {
		fmt.Fprintf(os.Stderr, "proofbench: %v\n", err)
		os.Exit(1)
	}

	nodes, err := collect(*feed, *sample)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proofbench: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("sample: %d distinct nodes from %s\n", len(nodes), *feed)

	arms := []arm{
		// The shipped settings, as the baseline every other arm is compared against.
		{name: "baseline (256, proof 6s, 3 urls)", concurrency: 256, proof: 6 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: nil},
		// INV-53 measured 1.07% at concurrency 256 against 2.25% at 24 on the same feed, and
		// attributed roughly a factor of two to our own load. This is that comparison.
		{name: "concurrency 24", concurrency: 24, proof: 6 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: nil},
		{name: "concurrency 64", concurrency: 64, proof: 6 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: nil},
		// A proxy adds its own handshake before the destination's, so 6s may simply be short.
		// The two nodes that did pass came in at 5.98s and 5.78s, against a 6s budget.
		{name: "proof 15s", concurrency: 256, proof: 15 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: nil},
		{name: "proof 15s + concurrency 24", concurrency: 24, proof: 15 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: nil},
		// Eight operators instead of two.
		{name: "8 endpoints", concurrency: 256, proof: 6 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: broadEndpoints},
		{name: "8 endpoints + proof 15s", concurrency: 256, proof: 15 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 900 * time.Millisecond, urls: broadEndpoints},
		// A hedge shorter than one tunnel handshake fires before the first probe could have
		// answered, so every node costs several requests. This checks the other direction.
		{name: "hedge 3s", concurrency: 256, proof: 15 * time.Second,
			reach: 1500 * time.Millisecond, hedge: 3 * time.Second, urls: nil},
		// Reach is a direct TCP dial from the runner. It cost 20,952 of 28,366 nodes in the live
		// run, and whether those nodes were dead or merely slow to accept is not recorded.
		{name: "reach 5s", concurrency: 256, proof: 15 * time.Second,
			reach: 5 * time.Second, hedge: 900 * time.Millisecond, urls: nil},
		{name: "no reach gate", concurrency: 256, proof: 15 * time.Second,
			hedge: 900 * time.Millisecond, urls: nil, skipReach: true},
		// The claim is a verified chain, not a status code. Reaching a response at all means the
		// chain verified, so a 429 is a node that carries TLS to the real destination and a
		// refusal that belongs to us. This is the arm that measures what the status check costs.
		// The decisive one. If a low concurrency with a generous budget still proves ~1%, the
		// figure is a property of the corpus and no setting will move it. If it jumps, the run is
		// competing with itself and the ceiling is ours to raise.
		{name: "gentle: 8, proof 20s", concurrency: 8, proof: 20 * time.Second,
			reach: 4 * time.Second, hedge: 4 * time.Second, urls: broadEndpoints},
	}

	fmt.Printf("\n%-30s %7s %6s %6s %7s %7s %7s\n",
		"arm", "reached", "proven", "rate", "dials", "d/node", "elapsed")
	fmt.Println(strings.Repeat("-", 78))

	type row struct {
		arm      arm
		reached  int
		proven   int
		elapsed  time.Duration
		failures map[string]int
		latency  []time.Duration
		dials    int64
	}
	var rows []row

	for _, a := range arms {
		if *only != "" && !strings.Contains(a.name, *only) {
			continue
		}
		r := run(a, nodes)
		rows = append(rows, row{a, r.reached, r.proven, r.elapsed, r.failures, r.latency, r.dials})

		rate, perNode := 0.0, 0.0
		if r.reached > 0 {
			rate = float64(r.proven) / float64(r.reached) * 100
			// Dials per node that got as far as the proof stage. One is the goal; three means a
			// dead node is costing three tunnel opens and three requests to the providers.
			perNode = float64(r.dials) / float64(r.reached)
		}
		fmt.Printf("%-30s %7d %6d %5.2f%% %7d %7.2f %7s\n", a.name, r.reached, r.proven, rate,
			r.dials, perNode, r.elapsed.Round(time.Second))
	}

	// The distributions are the point: a rate without them is another number nobody can act on.
	for _, r := range rows {
		fmt.Printf("\n%s — why the proof failed\n", r.arm.name)
		for _, k := range byCount(r.failures) {
			fmt.Printf("  %-58s %d\n", k, r.failures[k])
		}
		if len(r.latency) > 0 {
			sort.Slice(r.latency, func(i, j int) bool { return r.latency[i] < r.latency[j] })
			fmt.Printf("  proof latency: p50 %s  p90 %s  max %s\n",
				pct(r.latency, 50).Round(time.Millisecond),
				pct(r.latency, 90).Round(time.Millisecond),
				r.latency[len(r.latency)-1].Round(time.Millisecond))
		}
	}
}

type result struct {
	reached, proven int
	elapsed         time.Duration
	failures        map[string]int
	latency         []time.Duration
	// dials is how many times the tunnel was opened across the whole arm. Divided by the nodes
	// that got as far as the proof stage it is the figure that matters for load: one dial per
	// node is the goal, three is the predecessor's mistake wearing a different hat.
	dials int64
}

// countingDialer reports how much tunnel work an arm actually caused.
type countingDialer struct {
	inner tunnel.Dialer
	n     *atomic.Int64
}

func (d countingDialer) DialContext(ctx context.Context, t tunnel.Target, network, host string,
	port uint16) (net.Conn, error) {

	d.n.Add(1)
	return d.inner.DialContext(ctx, t, network, host, port)
}

func (d countingDialer) Close() error { return d.inner.Close() }

func run(a arm, nodes []model.Node) result {
	prover := verify.NewProver()
	if a.urls != nil {
		prover.URLs = a.urls
	}
	if a.hedge > 0 {
		prover.HedgeDelay = a.hedge
	}

	inner := tunnel.NewInProcess(tunnel.Config{})
	defer inner.Close()
	var dials atomic.Int64
	dialer := countingDialer{inner: inner, n: &dials}

	engine := verify.New(dialer, prover)
	engine.Resolver = policy.NewCachingResolver(policy.NewResolver(), 5*time.Minute)
	engine.SkipReach = a.skipReach
	engine.Budget = verify.Budget{
		Resolve:    2 * time.Second,
		Reach:      a.reach,
		Proof:      a.proof,
		Throughput: 0,
		// Total must not be the binding constraint when the point is to vary a stage.
		Total: 2*time.Second + a.reach + a.proof + 2*time.Second,
	}

	res := result{failures: map[string]int{}}
	var mu sync.Mutex
	scheduler := pipeline.NewScheduler(a.concurrency)

	started := time.Now()
	_ = pipeline.Each(context.Background(), scheduler, nodes, func(ctx context.Context, n model.Node) {
		v := engine.Verify(ctx, n)

		mu.Lock()
		defer mu.Unlock()
		if outcome, ok := v.Pass(model.StageReach); ok &&
			(outcome == model.OutcomePass || outcome == model.OutcomeSkipped) {
			res.reached++
		}
		if v.Proven {
			res.proven++
			res.latency = append(res.latency, v.Measured.Latency)
			return
		}
		stage, reason := v.FailedAt()
		if stage != model.StageProof {
			return
		}
		key := classify(reason)
		if byTransport {
			key = string(n.Identity.Transport) + " · " + key
		}
		res.failures[key]++
	})
	res.elapsed = time.Since(started)
	res.dials = dials.Load()
	return res
}

// rawErrors prints every proof error verbatim. Bucketing is what hid the cause in the first
// place, so the tool that exists to find it must be able to stop bucketing.
var rawErrors bool

// byTransport keys failures by transport. A transport-specific failure is a different problem
// from a node-specific one: it points at our construction, not at the node.
var byTransport bool

// classify buckets a raw proof error by what it actually says.
//
// This is deliberately finer than the pipeline's summariseReason, which folds every one of these
// into "no proof endpoint answered". That is right for a published funnel and useless for
// deciding what to change.
func classify(reason string) string {
	if rawErrors {
		if len(reason) > 240 {
			return reason[:240]
		}
		return reason
	}
	l := strings.ToLower(reason)
	switch {
	case strings.Contains(l, "answered 4"), strings.Contains(l, "answered 5"):
		// The endpoint replied with a status: it is up and refusing or redirecting us.
		if i := strings.Index(l, "answered "); i >= 0 && len(l) > i+13 {
			return "endpoint replied " + strings.TrimSpace(l[i+9:i+12]) + " (not a node fault)"
		}
		return "endpoint replied with an unexpected status"
	case strings.Contains(l, "answered 2"), strings.Contains(l, "answered 3"):
		return "endpoint replied 2xx/3xx instead of 204 (captive portal or wrong endpoint)"
	case strings.Contains(l, "certificate"), strings.Contains(l, "x509"):
		return "certificate did not verify (node interfering, or MITM)"
	case strings.Contains(l, "deadline exceeded"), strings.Contains(l, "timeout"):
		return "timed out inside the proof budget"
	case strings.Contains(l, "context canceled"):
		return "cancelled (the node budget ended first)"
	case strings.Contains(l, "connection reset"), strings.Contains(l, "forcibly closed"),
		strings.Contains(l, "wsarecv"):
		return "connection reset by the node or its network"
	case strings.Contains(l, "refused"):
		return "connection refused through the tunnel"
	case strings.Contains(l, "eof"):
		return "EOF: the tunnel closed mid-handshake"
	case strings.Contains(l, "tls"), strings.Contains(l, "handshake"):
		return "TLS handshake failed through the tunnel"
	case strings.Contains(l, "socket"), strings.Contains(l, "too many"):
		return "local socket exhaustion (our side, not the node)"
	default:
		if i := strings.LastIndex(l, ": "); i >= 0 && i+2 < len(l) {
			return "other: " + l[i+2:]
		}
		return "other: " + l
	}
}

// collect fetches one feed and returns up to n distinct decodable nodes.
func collect(feed string, n int) ([]model.Node, error) {
	fetcher := intake.NewFetcher(intake.DefaultLimits())
	body, err := fetcher.Fetch(context.Background(), feed)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	out := make([]model.Node, 0, n)
	for _, line := range body.Lines {
		res, derr := decode.Decode(line)
		if derr != nil {
			continue
		}
		key := res.Node.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, res.Node)
		if len(out) >= n {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no decodable nodes in %s", feed)
	}
	return out, nil
}

func byCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := len(sorted) * p / 100
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}
