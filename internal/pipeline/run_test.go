package pipeline

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/config"
	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/intake"
	"github.com/tuftytech/shellshift/internal/ledger"
	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/policy"
	"github.com/tuftytech/shellshift/internal/publish"
	"github.com/tuftytech/shellshift/internal/tunnel"
	"github.com/tuftytech/shellshift/internal/verify"
)

const uuid = "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b"

// directDialer stands in for a node that genuinely carries traffic.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, _ tunnel.Target, network, host string, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(port))))
}
func (directDialer) Close() error { return nil }

// refusingDialer carries traffic for every node except one, which is what a dead public proxy
// looks like from the verifier's side.
type refusingDialer struct{ host string }

func (d refusingDialer) DialContext(ctx context.Context, target tunnel.Target, network, host string, port uint16) (net.Conn, error) {
	if target.Node.Identity.Server == d.host {
		return nil, fmt.Errorf("dial %s: connection refused", d.host)
	}
	return directDialer{}.DialContext(ctx, target, network, host, port)
}
func (refusingDialer) Close() error { return nil }

// feedServer publishes a fixed feed over HTTPS.
func feedServer(t *testing.T, lines ...string) *httptest.Server {
	t.Helper()
	body := strings.Join(lines, "\n") + "\n"
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

func newRunner(t *testing.T, proofSrv *httptest.Server, feeds ...*httptest.Server) *Runner {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(proofSrv.Certificate())

	prover := verify.NewProver()
	prover.URLs = []string{proofSrv.URL + "/generate_204"}
	prover.RootCAs = pool

	engine := verify.New(directDialer{}, prover)
	engine.SkipReach = true
	engine.Resolver = &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}

	fetcher := intake.NewFetcher(intake.DefaultLimits())
	// Every feed server uses its own self-signed certificate, so the fetcher trusts them
	// all explicitly. Nothing here weakens verification: the pool is additive.
	feedPool := x509.NewCertPool()
	for _, f := range feeds {
		feedPool.AddCert(f.Certificate())
	}
	fetcher.Client = &http.Client{Transport: &http.Transport{
		TLSClientConfig: proofSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
	}}
	fetcher.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs = feedPool

	urls := make([]string, 0, len(feeds))
	for _, f := range feeds {
		urls = append(urls, f.URL)
	}

	return &Runner{
		Config:  config.Config{Sources: urls, Concurrency: 8},
		Fetcher: fetcher,
		Engine:  engine,
		Nodes:   ledger.New(ledger.DefaultPolicy()),
		Sources: ledger.NewSources(ledger.DefaultSourcePolicy()),
	}
}

func node(host string) string {
	return fmt.Sprintf("vless://%s@%s:443?type=tcp&security=tls&sni=%s", uuid, host, host)
}

// The whole cycle: fetch, decode, verify, account.
func TestRunProducesEntriesAndAnHonestFunnel(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	feed := feedServer(t,
		node("a.example.com"),
		node("b.example.com"),
		"vless://not-a-uuid@c.example.com:443?security=tls", // rejected: bad credential
		"# a comment",
	)
	defer feed.Close()

	r := newRunner(t, proof, feed)
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if res.Funnel.Collected != 3 {
		t.Fatalf("collected = %d, want 3 (the comment is not a candidate)", res.Funnel.Collected)
	}
	if res.Funnel.Decoded != 2 {
		t.Fatalf("decoded = %d, want 2", res.Funnel.Decoded)
	}
	if res.Funnel.Proven != 2 {
		t.Fatalf("proven = %d, want 2", res.Funnel.Proven)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(res.Entries))
	}
	if res.Rejections["bad_uuid"] != 1 {
		t.Fatalf("rejections = %v, want one bad_uuid", res.Rejections)
	}
	if res.FeedsFetched != 1 || res.FeedsFailed != 0 {
		t.Fatalf("feeds fetched=%d failed=%d", res.FeedsFetched, res.FeedsFailed)
	}
}

// INV-42. offered and proven must describe the same set, or every yield is wrong. The
// predecessor recorded a full parse count against a partial proven count and understated
// its yields roughly fourfold.
func TestSourceAccountingUsesTheSameSet(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	feed := feedServer(t, node("a.example.com"), node("b.example.com"))
	defer feed.Close()

	r := newRunner(t, proof, feed)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	st, ok := r.Sources.Stat(feed.URL)
	if !ok {
		t.Fatal("no record for the feed")
	}
	if st.Offered != 2 || st.Proven != 2 {
		t.Fatalf("offered=%d proven=%d, want 2 and 2", st.Offered, st.Proven)
	}
	if st.Yield() != 1 {
		t.Fatalf("yield = %v, want 1", st.Yield())
	}
}

// INV-40. Every collected line must end in exactly one bucket, and the arithmetic is checked
// rather than described.
//
// The invariant was written down in the predecessor and broken by construction anyway, so the
// test drives a cycle that populates every terminal bucket at once: a rejected line, a node
// two feeds both offer, a node that fails the proof, and a node that passes it. A funnel that
// balances only when nothing interesting happened is not evidence of anything.
func TestFunnelAccountsForEveryCollectedLine(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	// The two feeds overlap on a.example.com but are not byte-identical, so the mirror check
	// does not fire and deduplication is what removes the second copy.
	a := feedServer(t,
		node("a.example.com"),
		node("doomed.example.com"),
		"vless://not-a-uuid@c.example.com:443?security=tls", // rejected at decode
	)
	defer a.Close()
	b := feedServer(t,
		node("a.example.com"), // the duplicate
		node("b.example.com"),
	)
	defer b.Close()

	r := newRunner(t, proof, a, b)
	// One node cannot carry traffic at all, which is what a dead public proxy looks like from
	// here and what populates Failed.
	r.Engine = verify.New(refusingDialer{host: "doomed.example.com"}, r.Engine.Prover)
	r.Engine.SkipReach = true
	r.Engine.Resolver = &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	f := res.Funnel

	// Every bucket the equation names must actually be exercised, otherwise the assertion
	// below passes for the uninteresting reason that most terms are zero.
	if f.Rejected == 0 || f.Duplicates == 0 || f.Failed == 0 || f.Proven == 0 {
		t.Fatalf("the case must populate every bucket: rejected=%d duplicates=%d failed=%d proven=%d",
			f.Rejected, f.Duplicates, f.Failed, f.Proven)
	}
	if n := f.Unaccounted(); n != 0 {
		t.Fatalf("%+d of %d collected lines reached no bucket: "+
			"rejected=%d duplicates=%d deferred=%d not-attempted=%d failed=%d proven=%d",
			n, f.Collected, f.Rejected, f.Duplicates, f.Deferred, f.NotAttempted,
			f.Failed, f.Proven)
	}
	if f.Candidates != f.Decoded-f.Duplicates {
		t.Fatalf("candidates = %d, want decoded(%d) - duplicates(%d)",
			f.Candidates, f.Decoded, f.Duplicates)
	}

	// Failed must equal what the reason buckets add up to, or the reasons are a decoration
	// beside the count rather than an explanation of it (INV-41).
	var attributed int
	for _, n := range res.StageFailures {
		attributed += n
	}
	if attributed != f.Failed {
		t.Fatalf("failures attributed to a reason = %d, want %d: %v",
			attributed, f.Failed, res.StageFailures)
	}
}

// The accounting check must be able to fail. A gate that cannot fail is worse than no gate,
// and this one is arithmetic on a struct, so a leak is expressible directly (INV-40).
func TestUnaccountedDetectsALeak(t *testing.T) {
	balanced := publish.Funnel{
		Collected: 10, Rejected: 2, Duplicates: 1, Deferred: 2,
		NotAttempted: 1, Failed: 3, Proven: 1,
	}
	if n := balanced.Unaccounted(); n != 0 {
		t.Fatalf("a balanced funnel reports %+d", n)
	}

	// A node dropped without a counter — exactly the deduplication leak this invariant
	// closed — must surface as a positive discrepancy.
	leaked := balanced
	leaked.Duplicates = 0
	if n := leaked.Unaccounted(); n != 1 {
		t.Fatalf("an unrecorded drop reports %+d, want +1", n)
	}

	// Double counting is the opposite error and must not cancel out silently.
	doubled := balanced
	doubled.Proven += 2
	if n := doubled.Unaccounted(); n != -2 {
		t.Fatalf("a double-counted node reports %+d, want -2", n)
	}
}

// INV-42. What a truncated run publishes must be decided by expected yield, not by Go's map
// iteration order.
//
// The candidate set is a map, so the verification list was in randomised order. That is harmless
// while every candidate is verified and decisive the moment the budget runs out first — which at
// a hundred thousand candidates it always does. The published subscriptions then contain an
// arbitrary subset, and a different arbitrary subset every run.
func TestVerificationOrderPrefersProvenThenHighYield(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()
	feed := feedServer(t, node("a.example.com"))
	defer feed.Close()

	r := newRunner(t, proof, feed)

	// A rich feed and a poor one, plus one node already proven from a third.
	const rich, poor, other = "https://rich.example", "https://poor.example", "https://other.example"
	r.Sources.RecordRun(rich, 100, 48) // 48% yield: the shape of the real corpus
	r.Sources.RecordRun(poor, 100, 1)

	mk := func(host, src string) model.Node {
		res, err := decode.Decode(node(host))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		n := res.Node
		n.Source = src
		return n
	}

	provenNode := mk("proven.example.com", other)
	r.Nodes.Observe(provenNode.Key())
	r.Nodes.RecordProof(provenNode.Key())

	// Deliberately worst-case input order: the best candidate last.
	due := []model.Node{
		mk("p1.example.com", poor),
		mk("r1.example.com", rich),
		mk("p2.example.com", poor),
		mk("r2.example.com", rich),
		provenNode,
	}
	r.orderDue(due)

	if due[0].Key() != provenNode.Key() {
		t.Fatalf("a node with a proof on record must be verified first, got %s",
			due[0].Identity.Server)
	}
	// Then the rich feed's nodes, before the poor feed's.
	for i, want := range []string{rich, rich, poor, poor} {
		if got := due[i+1].Source; got != want {
			t.Fatalf("position %d came from %s, want %s (order: %v)", i+1, got, want, sources(due))
		}
	}

	// And the order must be identical across runs, or the published set churns among equals for
	// no reason connected to the nodes.
	shuffled := []model.Node{due[3], due[0], due[4], due[1], due[2]}
	r.orderDue(shuffled)
	for i := range due {
		if due[i].Key() != shuffled[i].Key() {
			t.Fatalf("ordering is not deterministic:\n  %v\n  %v", sources(due), sources(shuffled))
		}
	}
}

func sources(nodes []model.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Identity.Server+"<-"+n.Source)
	}
	return out
}

// INV-24. Two feeds serving identical bytes are parsed once.
func TestMirroredFeedsAreParsedOnce(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	a := feedServer(t, node("a.example.com"))
	defer a.Close()
	b := feedServer(t, node("a.example.com"))
	defer b.Close()

	r := newRunner(t, proof, a, b)
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.MirroredFeeds != 1 {
		t.Fatalf("mirrored = %d, want 1", res.MirroredFeeds)
	}
	if res.Funnel.Collected != 1 {
		t.Fatalf("collected = %d, want 1: the mirror should not be re-parsed", res.Funnel.Collected)
	}
}

// A node in backoff is not re-verified. The predecessor had no such notion and spent full
// verification on every pooled node every run, including those already failing.
func TestNodesInBackoffAreSkipped(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	feed := feedServer(t, node("a.example.com"))
	defer feed.Close()

	r := newRunner(t, proof, feed)
	first, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(first.Entries) != 1 {
		t.Fatalf("first run produced %d entries", len(first.Entries))
	}

	// Mark it failed so it enters backoff, then run again.
	r.Nodes.RecordFailure(first.Entries[0].Node.Key())

	second, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.SkippedInBackoff != 1 {
		t.Fatalf("skipped = %d, want 1", second.SkippedInBackoff)
	}
	if len(second.Entries) != 0 {
		t.Fatalf("a node in backoff must not be verified again yet")
	}
}

// A count without a reason is the same defect this project criticises in its predecessor,
// applied to feeds instead of nodes: a live run reported one feed failed and the cause had
// to be found by hand.
func TestFeedFailuresCarryAReason(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	good := feedServer(t, node("a.example.com"))
	defer good.Close()
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()

	r := newRunner(t, proof, good, bad)
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.FeedsFailed != 1 {
		t.Fatalf("failed = %d, want 1", res.FeedsFailed)
	}
	why, ok := res.FeedFailures[bad.URL]
	if !ok || why == "" {
		t.Fatalf("the failure must carry a reason, got %q", why)
	}
	if !strings.Contains(why, "404") {
		t.Fatalf("reason = %q, want it to name the status", why)
	}
}

// The funnel must distinguish "not attempted" from "failed the first stage". Without it a
// run that ran out of budget publishes a yield that is wrong with nothing to indicate it —
// the exact defect this project criticises in its predecessor telemetry (INV-42).
func TestFunnelSeparatesNotAttempted(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow enough that the run budget expires first.
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer proof.Close()

	lines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		lines = append(lines, node(fmt.Sprintf("h%d.example.com", i)))
	}
	feed := feedServer(t, lines...)
	defer feed.Close()

	r := newRunner(t, proof, feed)
	r.Config.Concurrency = 2
	r.Config.RunBudget = config.Duration(400 * time.Millisecond)

	res, _ := r.Run(context.Background())
	if !res.Funnel.BudgetExhausted {
		t.Fatal("the run should have recorded that its budget was exhausted")
	}
	if res.Funnel.NotAttempted <= 0 {
		t.Fatalf("not attempted = %d, want a positive count", res.Funnel.NotAttempted)
	}
	if res.Funnel.Proven != 0 {
		t.Fatalf("proven = %d, want 0", res.Funnel.Proven)
	}
}

// A class that is empty because the feeds failed to load must not look like a class that is
// empty because no node qualified. That confusion is how the predecessor shipped a subscription
// nobody could ever use, for months, without noticing.
func TestClassificationReportsWhyAClassIsEmpty(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	feed := feedServer(t, node("a.example.com"))
	defer feed.Close()

	t.Run("no classifier at all is reported", func(t *testing.T) {
		r := newRunner(t, proof, feed)
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Classified != 0 {
			t.Fatalf("classified = %d, want 0", res.Classified)
		}
		if res.ClassReasons["classifier not configured"] != len(res.Entries) {
			t.Fatalf("reasons = %v, want every node attributed", res.ClassReasons)
		}
	})

	t.Run("an unavailable whitelist is reported", func(t *testing.T) {
		r := newRunner(t, proof, feed)
		r.Classifier = policy.NewClassifier(policy.NewWhitelist(), nil)
		res, err := r.Run(context.Background())
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if res.Classified != 0 {
			t.Fatalf("classified = %d, want 0", res.Classified)
		}
		// The node is not reality, so that is the honest reason here; what matters is that a
		// reason exists for every node rather than a silent zero.
		total := 0
		for _, n := range res.ClassReasons {
			total += n
		}
		if total != len(res.Entries) {
			t.Fatalf("reasons account for %d of %d nodes: %v", total, len(res.Entries), res.ClassReasons)
		}
	})
}

// Countries are absent rather than unknown, and a node keeps its verdict either way.
func TestGeographyIsOptionalAndNonFatal(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	feed := feedServer(t, node("a.example.com"))
	defer feed.Close()

	r := newRunner(t, proof, feed)
	// A locator pointed at nothing: the lookup fails and the run continues.
	geo := policy.NewGeoLocator()
	geo.Endpoint = "http://127.0.0.1:1/batch"
	geo.Pacing = 0
	r.Geo = geo
	r.Resolver = &policy.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d, want 1: a failed geo lookup must not lose a node", len(res.Entries))
	}
	if res.Entries[0].Node.Country != "" {
		t.Fatalf("country = %q, want empty rather than a placeholder", res.Entries[0].Node.Country)
	}
}

// A proof failure must be countable by what actually went wrong, not by the fact that it was a
// proof failure.
//
// Every proof error is wrapped by the prover as "no proof URL answered: %w", and
// summariseReason's needle list is first-match-wins with that exact phrase at the top. So a 403
// from Cloudflare, a timeout, a reset and a certificate error all collapsed into one bucket —
// and the seventeen more specific buckets below it were unreachable for the one stage the whole
// project is about.
//
// The distinction is not cosmetic. A 403 over a verified chain means the node carried our traffic
// and the endpoint refused its IP; a timeout means the node did not carry our traffic. They imply
// opposite actions, and a live sample of the published catalogue put 113 of 131 reached nodes in
// the first category while the operator's output could only say "no proof endpoint answered".
func TestProofFailuresAreCountedByWhatWentWrong(t *testing.T) {
	// Verbatim shapes, as the prover wraps them.
	const (
		forbidden = `no proof URL answered: Get "https://cp.cloudflare.com/generate_204": ` +
			`unexpected HTTP response status: 403`
		tooMany = `no proof URL answered: Get "https://www.gstatic.com/generate_204": ` +
			`unexpected HTTP response status: 429`
		deadline = "no proof URL answered: context deadline exceeded"
		badChain = `no proof URL answered: Get "https://cp.cloudflare.com/generate_204": ` +
			`tls: failed to verify certificate: x509: certificate signed by unknown authority`
		reset = `no proof URL answered: Get "https://www.gstatic.com/generate_204": ` +
			`read tcp 10.0.0.1:1080: connection reset by peer`
	)

	buckets := map[string]string{}
	for _, r := range []string{forbidden, tooMany, deadline, badChain, reset} {
		buckets[r] = summariseReason(r)
	}
	// Five different conditions must not be one bucket.
	distinct := map[string]bool{}
	for _, b := range buckets {
		distinct[b] = true
	}
	if len(distinct) < 4 {
		t.Errorf("five proof failures collapsed into %d bucket(s): %v", len(distinct), distinct)
	}

	// And each one has to name its own condition.
	for reason, want := range map[string]string{
		forbidden: "403",
		tooMany:   "rate limited",
		deadline:  "timed out",
		badChain:  "certificate",
		reset:     "connection reset",
	} {
		if got := summariseReason(reason); !strings.Contains(got, want) {
			t.Errorf("summariseReason(%.60q...)\n  = %q\n  want something containing %q",
				reason, got, want)
		}
	}
}

// A failure that is not a proof failure keeps being classified as before: the wrapper is what
// gets stripped, not the classification.
func TestNonProofFailuresKeepTheirBuckets(t *testing.T) {
	for reason, want := range map[string]string{
		"dial tcp 198.51.100.1:443: i/o timeout":        "timed out",
		"egress denied: 127.0.0.1 is loopback":          "egress denied",
		"dial tcp 198.51.100.2:443: connection refused": "connection refused",
	} {
		if got := summariseReason(reason); got != want {
			t.Errorf("summariseReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

// realityNode is a node the classifier can actually reach a verdict about: the whitelisted class
// is about a disguise only Reality provides, so a TLS node is answered with "not reality" before
// any context is consulted and would make the test below vacuous.
func realityNode(host string) string {
	return fmt.Sprintf("vless://%s@%s:443?type=tcp&security=reality&sni=%s&pbk=%s&sid=6ba85179e3&fp=chrome",
		uuid, host, host, pbk)
}

const pbk = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

// watchingResolver records the state of every context it is handed, so a test can see whether the
// stage that called it was still allowed to do work.
//
// It refuses after recording rather than answering, in the one place that would otherwise open a
// socket to a real address: the question here is which context a stage was given, not whether a
// cover site exists.
type watchingResolver struct {
	addr   netip.Addr
	refuse bool

	mu    sync.Mutex
	calls int
	errs  []error
}

func (r *watchingResolver) Resolve(ctx context.Context, _ string) (netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.errs = append(r.errs, ctx.Err())
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if r.refuse {
		return netip.Addr{}, fmt.Errorf("resolver refused on purpose")
	}
	return r.addr, nil
}

// state is the number of calls and the first dead context among them.
func (r *watchingResolver) state() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, err := range r.errs {
		if err != nil {
			return r.calls, err
		}
	}
	return r.calls, nil
}

// geoBatchServer answers the batch geo API with a fixed table.
func geoBatchServer(t *testing.T, answers map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var queries []string
		if err := json.NewDecoder(r.Body).Decode(&queries); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		type row struct {
			Query       string `json:"query"`
			Status      string `json:"status"`
			CountryCode string `json:"countryCode"`
			Country     string `json:"country"`
		}
		out := make([]row, 0, len(queries))
		for _, q := range queries {
			if cc, ok := answers[q]; ok {
				out = append(out, row{Query: q, Status: "success", CountryCode: cc, Country: "Netherlands"})
				continue
			}
			out = append(out, row{Query: q, Status: "fail"})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

// Classification and geography are not on the verification clock, and a run that spent all of it
// still produces a class and a country.
//
// The run budget is a ceiling on verification — the stage that dials tens of thousands of
// third-party hosts — and it used to be handed to the two stages that follow. On any run large
// enough to reach the budget, which is the normal case at thirty thousand candidates, every
// masking proof then failed on a dead context and the geo lookup returned before its first
// request. The catalogue published as all-open with no countries, and nothing in the output said
// that the deadline rather than the data had produced it: an empty whitelisted class reads exactly
// like a class nobody qualified for, which is the confusion the class-reason histogram exists to
// remove. This is that defect one layer up — the reason would have said "masking could not be
// proven" and been technically true.
func TestClassificationAndGeographyOutliveTheRunBudget(t *testing.T) {
	// The first proof answers and every later one stalls, which produces the state the defect
	// needed: a survivor to classify, and a budget that ran out before the run was done.
	var answered atomic.Int64
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answered.Add(1) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		<-r.Context().Done()
	}))
	defer proof.Close()

	hosts := make([]string, 0, 6)
	lines := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		host := fmt.Sprintf("r%d.example.com", i)
		hosts = append(hosts, host)
		lines = append(lines, realityNode(host))
	}
	feed := feedServer(t, lines...)
	defer feed.Close()

	geo := geoBatchServer(t, map[string]string{"93.184.216.34": "NL"})
	defer geo.Close()

	r := newRunner(t, proof, feed)
	r.Config.Concurrency = 2
	r.Config.RunBudget = config.Duration(700 * time.Millisecond)

	wl := policy.NewWhitelist()
	if _, err := wl.AddDomains(strings.NewReader(strings.Join(hosts, "\n"))); err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	masking := &watchingResolver{addr: netip.MustParseAddr("93.184.216.34"), refuse: true}
	r.Classifier = policy.NewClassifier(wl, policy.NewMaskingProver(masking))

	located := &watchingResolver{addr: netip.MustParseAddr("93.184.216.34")}
	r.Resolver = located
	locator := policy.NewGeoLocator()
	locator.Endpoint = geo.URL
	locator.Pacing = 0
	locator.Client = geo.Client()
	r.Geo = locator

	res, _ := r.Run(context.Background())

	// The premise. Without an exhausted budget this test proves nothing at all.
	if !res.Funnel.BudgetExhausted {
		t.Fatal("the budget did not run out; the fixture is not reproducing the conditions")
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %d, want exactly the one node whose proof was answered", len(res.Entries))
	}

	// Classification ran on a live context. The prover is asked once per distinct server name
	// and refuses on purpose, so what is asserted is the context it was handed.
	calls, dead := masking.state()
	if calls == 0 {
		t.Fatal("the masking proof was never attempted: the node was not Reality, or not on " +
			"the whitelist, so the context this test is about was never consulted")
	}
	if dead != nil {
		t.Errorf("the masking proof was handed a context that was already over: %v", dead)
	}

	// Every survivor is attributed, and the reason is the proof rather than a deadline.
	total := 0
	for _, n := range res.ClassReasons {
		total += n
	}
	if total != len(res.Entries) {
		t.Errorf("reasons account for %d of %d survivors: %v", total, len(res.Entries), res.ClassReasons)
	}
	if n := res.ClassReasons[string(policy.ReasonMaskingUnproven)]; n != len(res.Entries) {
		t.Errorf("masking-unproven = %d, want %d: %v", n, len(res.Entries), res.ClassReasons)
	}

	// And the country arrived, which is the visible half of the same collapse: the geo stage
	// used to return before its first request and the whole catalogue published without one.
	if calls, dead := located.state(); calls == 0 || dead != nil {
		t.Errorf("the geo stage resolved %d addresses, first dead context %v", calls, dead)
	}
	if res.GeoResolved != len(res.Entries) {
		t.Errorf("geo resolved = %d, want %d", res.GeoResolved, len(res.Entries))
	}
	if cc := res.Entries[0].Node.Country; cc != "NL" {
		t.Errorf("country = %q, want NL", cc)
	}
}

// The reason a node is in its class travels with the node, not only in the run's histogram.
//
// The histogram answers "why is this class small" and it is the only thing publication used to
// carry, so the page could tell a reader that 738 nodes failed the whitelist test and could not
// tell them why *their* node did. Those are different questions with the same data behind them,
// and one node's answer is the one a person actually wants.
func TestTheClassReasonTravelsWithTheNode(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	feed := feedServer(t, node("a.example.com"), realityNode("r.example.com"))
	defer feed.Close()

	r := newRunner(t, proof, feed)
	// An empty whitelist that has not loaded: the reality node gets "whitelist unavailable" and
	// the plain TLS node gets "not reality", so two different reasons are exercised at once.
	r.Classifier = policy.NewClassifier(policy.NewWhitelist(), nil)

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Entries) == 0 {
		t.Fatal("no entries survived; the fixture proves nothing")
	}

	counted := map[string]int{}
	for _, e := range res.Entries {
		if e.Node.ClassReason == "" {
			t.Errorf("node %s carries no class reason", e.Node.Short())
			continue
		}
		counted[e.Node.ClassReason]++
	}
	for reason, n := range counted {
		if res.ClassReasons[reason] != n {
			t.Errorf("reason %q counted %d on nodes and %d in the histogram: the two must be "+
				"the same data", reason, n, res.ClassReasons[reason])
		}
	}

	// The reason has to be the one the classifier actually gave, not a default: an unloaded
	// whitelist and a non-Reality node are different findings and the page says which.
	seen := map[string]bool{}
	for _, e := range res.Entries {
		seen[e.Node.ClassReason] = true
	}
	if !seen[string(policy.ReasonNotReality)] {
		t.Errorf("the plain TLS node should read %q; reasons seen: %v",
			policy.ReasonNotReality, seen)
	}
}
