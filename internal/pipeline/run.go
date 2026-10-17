package pipeline

import (
	"context"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tuftytech/shellshift/internal/config"
	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/intake"
	"github.com/tuftytech/shellshift/internal/ledger"
	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/policy"
	"github.com/tuftytech/shellshift/internal/publish"
	"github.com/tuftytech/shellshift/internal/verify"
)

// Runner executes one collection cycle.
type Runner struct {
	Config  config.Config
	Fetcher *intake.Fetcher
	Engine  *verify.Engine
	Nodes   *ledger.Ledger
	Sources *ledger.Sources

	// Resolver is shared with the engine so the addresses already resolved during
	// verification are reused rather than looked up again.
	Resolver policy.AddressResolver
	// Classifier decides the bypass class. Nil means every node is open and the run reports
	// that the class was not computed — which is different from computing it and finding
	// nothing.
	Classifier *policy.Classifier
	// Geo fills in country codes. Nil means countries are absent, not unknown.
	Geo *policy.GeoLocator

	// Now is injectable so a test can assert timing without waiting.
	Now func() time.Time
}

// Result is everything one cycle produced.
type Result struct {
	Entries    []publish.Entry
	Funnel     publish.Funnel
	Rejections map[string]int
	Streaks    map[string]int
	Elapsed    time.Duration
	// SkippedInBackoff counts nodes the ledger said were not worth a full verification
	// yet. The predecessor had no such notion and re-verified every pooled node at full
	// cost every run, including the 367 of 1,232 that were already failing.
	SkippedInBackoff int
	// FeedsFetched and FeedsFailed separate a feed that could not be retrieved from one
	// that returns nodes which do not work.
	FeedsFetched, FeedsFailed int
	// FeedFailures records why each feed could not be fetched.
	//
	// A count without a reason is the same defect this project criticises in its
	// predecessor, applied to feeds instead of nodes: a live run reported one feed failed
	// and the cause — a 99.8 MiB body over the transfer cap — had to be found by hand.
	FeedFailures map[string]string
	// MirroredFeeds counts feeds skipped because another feed served identical bytes.
	MirroredFeeds int
	// ClassReasons counts why nodes landed outside the whitelisted class. Without this a
	// class that is empty because the feeds failed to load looks exactly like a class that is
	// empty because no node qualified — which is how the predecessor shipped a subscription
	// nobody could ever use.
	ClassReasons map[string]int
	// History is what the ledger remembers about each surviving node, keyed by node key: how
	// many runs proved it, how many failed it, when it was first seen. The ledger has held this
	// since it was written and publication never asked for it, so the page could say a node
	// passed today and nothing about whether it passes every day.
	History map[string]publish.NodeHistory
	// Covers is the certificate the masking proof saw, keyed by the probed server name. One
	// entry serves every node naming that site, which is why the proof is affordable at all.
	Covers map[string]policy.CoverCert
	// Classified counts how many nodes reached the whitelisted class.
	Classified int
	// GeoResolved counts nodes that acquired a country.
	GeoResolved int
	// StageFailures counts why nodes failed, keyed by stage and reason.
	//
	// Without it the funnel shows how many nodes reached a stage and how many passed, and the
	// difference is unattributed — which is the same defect this project criticises in its
	// predecessor telemetry, applied to verification instead of decoding. A run where every
	// node fails the proof for one shared reason looks identical to a run against dead feeds.
	StageFailures map[string]int
	// TruncatedFeeds counts feeds that hit the candidate cap, so a shortened feed is
	// distinguishable from a feed that got smaller.
	TruncatedFeeds int
}

// Run performs intake, decoding, verification and assembly.
//
// What it does not do is publish. Assembling a result and deciding whether that result may
// replace what is already live are separate responsibilities, because in the predecessor
// they were entangled: publication failure handling lived inside the presentation code, and
// a run with no surviving nodes emptied every subscription file on its way out (INV-43).
func (r *Runner) Run(ctx context.Context) (Result, error) {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	started := now()

	if budget := r.Config.RunBudget.Duration(); budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	res := Result{
		Rejections:    map[string]int{},
		Streaks:       map[string]int{},
		FeedFailures:  map[string]string{},
		ClassReasons:  map[string]int{},
		StageFailures: map[string]int{},
		History:       map[string]publish.NodeHistory{},
		Covers:        map[string]policy.CoverCert{},
	}

	// --- intake ---------------------------------------------------------------
	candidates, seenDigest := map[string]model.Node{}, map[string]bool{}
	offeredBySource := map[string]int{}

	for _, src := range r.orderedSources() {
		if retired, _ := r.Sources.Retired(src); retired {
			continue
		}
		body, err := r.Fetcher.Fetch(ctx, src)
		if err != nil {
			r.Sources.RecordFetchFailure(src)
			res.FeedsFailed++
			res.FeedFailures[src] = err.Error()
			continue
		}
		res.FeedsFetched++
		if body.Truncated {
			res.TruncatedFeeds++
		}

		// Two feeds serving identical bytes are parsed once (INV-24).
		if seenDigest[body.Digest] {
			res.MirroredFeeds++
			continue
		}
		seenDigest[body.Digest] = true

		for _, line := range body.Lines {
			res.Funnel.Collected++
			out, derr := decode.Decode(line)
			if derr != nil {
				reason, ok := decode.ReasonOf(derr)
				if !ok {
					reason = "unclassified"
				}
				res.Rejections[string(reason)]++
				continue
			}
			res.Funnel.Decoded++
			node := out.Node
			node.Source = src
			key := node.Key()
			if _, dup := candidates[key]; dup {
				// Counted, not merely skipped. A popular node appears in several feeds, and
				// without this counter the drop from Decoded to the candidate set is
				// attributed nowhere (INV-40).
				res.Funnel.Duplicates++
				continue
			}
			candidates[key] = node
			offeredBySource[src]++
			r.Nodes.Observe(key)
		}
	}

	res.Funnel.Candidates = len(candidates)
	for _, n := range res.Rejections {
		res.Funnel.Rejected += n
	}

	// --- verification ---------------------------------------------------------
	due := make([]model.Node, 0, len(candidates))
	for key, node := range candidates {
		if !r.Nodes.DueForCheck(key) {
			res.SkippedInBackoff++
			continue
		}
		due = append(due, node)
	}

	// Verification order decides what a truncated run publishes.
	//
	// The list is built by walking a map, so without this it is in Go's randomised map order. That
	// is harmless while every candidate gets verified and decisive as soon as the budget runs out
	// first — which at a hundred thousand candidates it always will. An arbitrary subset of the
	// catalogue is then what reaches the subscriptions, and it is a different arbitrary subset
	// every run, so the published set churns for reasons that have nothing to do with the nodes.
	//
	// The feed list is already ordered by yield on the way in (orderedSources), and that ordering
	// is exactly what a map obliterates. Restoring it here spends the scarce part of the budget —
	// the proof stage — on the candidates most likely to survive it.
	r.orderDue(due)

	res.Funnel.Deferred = res.SkippedInBackoff

	scheduler := NewScheduler(r.Config.Concurrency)
	var (
		mu             sync.Mutex
		verdicts       = make([]publish.Entry, 0, len(due))
		provenBySource = map[string]int{}
		attempted      int
	)

	if err := Each(ctx, scheduler, due, func(ctx context.Context, node model.Node) {
		v := r.Engine.Verify(ctx, node)

		mu.Lock()
		defer mu.Unlock()
		attempted++

		// Stage counters are recorded per stage rather than folded together, which is what
		// makes the funnel honest (INV-41).
		if outcome, ok := v.Pass(model.StagePolicy); ok && outcome == model.OutcomePass {
			res.Funnel.Policy++
		}
		if outcome, ok := v.Pass(model.StageReach); ok &&
			(outcome == model.OutcomePass || outcome == model.OutcomeSkipped) {
			res.Funnel.Reached++
		}
		if !v.Proven {
			r.Nodes.RecordFailure(node.Key())
			res.Funnel.Failed++
			if stage, reason := v.FailedAt(); stage != "" {
				res.StageFailures[string(stage)+": "+summariseReason(reason)]++
			} else {
				// Unreachable with the current engine: every path that leaves Proven false
				// appends a failing stage first. It is here because the accounting must not
				// depend on that being true — a future early return without a stage would
				// otherwise produce a node counted in Failed and absent from every reason
				// bucket, which is the shape INV-41 exists to prevent. Named so that if it
				// ever fires, it reads as a defect rather than a category.
				res.StageFailures["unattributed: no stage reported a failure"]++
			}
			return
		}
		res.Funnel.Proven++
		r.Nodes.RecordProof(node.Key())
		provenBySource[node.Source]++
		verdicts = append(verdicts, publish.Entry{Node: node, Verdict: v})
	}); err != nil {
		// Running out of budget is not a failure of the run, but it must be visible: a
		// funnel that cannot distinguish "not attempted" from "failed the first stage"
		// publishes a yield that is wrong with nothing to indicate it.
		res.Funnel.BudgetExhausted = true
		if len(verdicts) == 0 {
			res.Funnel.NotAttempted = len(due) - attempted
			return res, err
		}
	}
	res.Funnel.NotAttempted = len(due) - attempted

	// --- accounting -----------------------------------------------------------
	// offered and proven describe the same set of nodes. Recording a full parse count
	// against a partial proven count is what made the predecessor telemetry understate
	// every yield roughly fourfold (INV-42).
	for src, offered := range offeredBySource {
		r.Sources.RecordRun(src, offered, provenBySource[src])
	}
	for _, e := range verdicts {
		if entry, ok := r.Nodes.Get(e.Node.Key()); ok {
			res.Streaks[e.Node.Key()] = entry.Streak
			res.History[e.Node.Key()] = publish.NodeHistory{
				Proofs: entry.Proofs, Failures: entry.Failures, FirstSeen: entry.FirstSeen,
			}
		}
	}

	// --- classification and geography ----------------------------------------
	// Both happen after verification and only for survivors: classifying a node that failed
	// is work spent on something nobody will see.
	//
	// Neither gets the verification context, and that is the fix for a silent collapse. The
	// run budget is a ceiling on verification — the stage that dials tens of thousands of
	// third-party hosts — and handing its exhausted deadline to the two stages that follow
	// meant that on any run large enough to hit the budget, which is the normal case at
	// thirty thousand candidates, every masking proof failed on a dead context and the geo
	// lookup returned before its first request. The catalogue then published as
	// all-open with no countries, and nothing in the output said the deadline rather than
	// the data had produced that: an empty whitelisted class reads exactly like a class
	// nobody qualified for. These stages are bounded on their own, because "not the run
	// budget" must not mean "unbounded".
	post, cancelPost := context.WithTimeout(context.WithoutCancel(ctx), postVerificationBudget)
	defer cancelPost()
	r.classify(post, verdicts, &res)
	r.locate(post, verdicts, &res)

	res.Entries = verdicts
	res.Elapsed = now().Sub(started)
	return res, nil
}

// postVerificationBudget bounds classification and geography together.
//
// It is generous because masking is proved once per distinct server name rather than once per
// node and the geo lookups are batched, so the real cost is a few hundred handshakes; and it
// exists at all because replacing an exhausted deadline with no deadline would turn a silent
// collapse into a run that never ends.
const postVerificationBudget = 3 * time.Minute

// classify assigns the bypass class to every surviving node.
func (r *Runner) classify(ctx context.Context, entries []publish.Entry, res *Result) {
	if r.Classifier == nil {
		// Stamped on every node too, and not only counted: a card that says nothing about the
		// class is indistinguishable from a card whose node failed the check, and "the check was
		// not configured for this run" is the one answer a reader cannot guess.
		const unconfigured = "classifier not configured"
		res.ClassReasons[unconfigured] = len(entries)
		for i := range entries {
			entries[i].Node.ClassReason = unconfigured
		}
		return
	}
	for i := range entries {
		class, reason := r.Classifier.Classify(ctx, entries[i].Node)
		entries[i].Node.Class = class
		// Both, from one call: the histogram is the run's summary and the node's own copy is
		// what a reader asking about their own node needs. Deriving one from the other later is
		// impossible in the direction that matters.
		entries[i].Node.ClassReason = string(reason)
		res.ClassReasons[string(reason)]++
		// The evidence behind the decision, not just the decision. The prover holds one record
		// per distinct name, so this loop reads rather than probes.
		if r.Classifier.Masking != nil {
			if name := policy.CoverName(entries[i].Node); name != "" {
				if cover, ok := r.Classifier.Masking.Cover(name); ok {
					res.Covers[name] = cover
				}
			}
		}
		if class == model.ClassWhitelisted {
			res.Classified++
		}
	}
}

// locate fills in country codes for surviving nodes.
//
// The address is taken from the resolver, which already answered for this host during
// verification, so the country costs one batch request per distinct network rather than a
// lookup per node.
func (r *Runner) locate(ctx context.Context, entries []publish.Entry, res *Result) {
	if r.Geo == nil || r.Resolver == nil {
		return
	}

	addrByNode := make(map[int]netip.Addr, len(entries))
	unique := make([]netip.Addr, 0, len(entries))
	seen := map[netip.Addr]bool{}
	for i := range entries {
		addr, err := r.Resolver.Resolve(ctx, entries[i].Node.Identity.Server)
		if err != nil {
			continue
		}
		addrByNode[i] = addr
		// Recorded whether or not the geo lookup answers: the address is what verification
		// actually dialled, and it is a fact about the node either way.
		entries[i].Node.Addr = addr.String()
		if !seen[addr] {
			seen[addr] = true
			unique = append(unique, addr)
		}
	}

	places := r.Geo.Lookup(ctx, unique)
	for i, addr := range addrByNode {
		if p, ok := places[addr.String()]; ok {
			entries[i].Node.Country = p.CC
			entries[i].Node.CountryName = p.Country
			entries[i].Node.City = p.City
			entries[i].Node.Timezone = p.Timezone
			entries[i].Node.ASN = p.ASN
			entries[i].Node.ASName = p.ASName
			entries[i].Node.ISP = p.ISP
			entries[i].Node.Org = p.Org
			entries[i].Node.Reverse = p.Reverse
			res.GeoResolved++
		}
	}
}

// orderDue sorts candidates so that a run which cannot finish still verifies the ones most
// likely to pass.
//
// Three keys, in order:
//
//  1. Nodes with a proof on record first. A node that worked last run is the best single
//     predictor available of a node that works this run, and it is also what the visitor sees as
//     continuity rather than a subscription that reshuffles wholesale every four hours.
//  2. Then by the yield of the feed that offered it. Measured on the real corpus, one feed
//     produced 48 percent of all working nodes from 3 percent of the parse volume, so this is
//     not a marginal signal.
//  3. Then by identity, which is stable across runs. Without a deterministic tie-break the
//     order still wobbles between runs among equals, and the published set wobbles with it.
func (r *Runner) orderDue(due []model.Node) {
	type rank struct {
		proven bool
		yield  float64
	}
	ranks := make(map[string]rank, len(due))
	for _, n := range due {
		key := n.Key()
		if _, ok := ranks[key]; ok {
			continue
		}
		var rk rank
		if entry, ok := r.Nodes.Get(key); ok {
			rk.proven = entry.Proofs > 0
		}
		if st, ok := r.Sources.Stat(n.Source); ok {
			rk.yield = st.Yield()
		}
		ranks[key] = rk
	}

	sort.SliceStable(due, func(i, j int) bool {
		a, b := ranks[due[i].Key()], ranks[due[j].Key()]
		if a.proven != b.proven {
			return a.proven
		}
		if a.yield != b.yield {
			return a.yield > b.yield
		}
		return due[i].Key() < due[j].Key()
	})
}

// orderedSources returns the feed list with the highest-yield feeds first.
//
// Order matters because the run has a budget: in the observed corpus one feed produced 48
// percent of all working nodes from 3 percent of the parse volume. A feed with no record
// yet goes at the front, so a new source is never starved by an established one.
func (r *Runner) orderedSources() []string {
	ranked := r.Sources.Ranked()
	position := make(map[string]int, len(ranked))
	for i, st := range ranked {
		position[st.URL] = i + 1
	}

	unknown := make([]string, 0, len(r.Config.Sources))
	known := make([]string, 0, len(r.Config.Sources))
	for _, src := range r.Config.Sources {
		if position[src] == 0 {
			unknown = append(unknown, src)
			continue
		}
		known = append(known, src)
	}
	sortByPosition(known, position)
	return append(unknown, known...)
}

func sortByPosition(items []string, position map[string]int) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && position[items[j]] < position[items[j-1]]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// proofWrapper is how the prover wraps every proof failure before it reaches here. It is
// stripped rather than matched, and that is the whole point of it being named: see
// summariseReason.
const proofWrapper = "no proof url answered: "

// statusRe pulls the HTTP status out of a proof failure. A status is the one failure shape that
// says the tunnel worked — the request completed and something answered — so it must not be
// counted next to a timeout.
var statusRe = regexp.MustCompile(`status:?\s*(\d{3})`)

// summariseReason collapses a failure message into something countable.
//
// Raw messages carry addresses, ports and timings, so counting them verbatim produces one bucket
// per node and says nothing. The goal is the opposite: a handful of buckets, so that a run where
// every node failed for one shared reason is immediately distinguishable from a run against dead
// feeds.
//
// The prover's wrapper is stripped before anything is matched. It used to be the first needle in
// the list below, and the list is first-match-wins, so every failure at the proof stage — a 403
// from Cloudflare, a timeout, a reset, a bad chain — became the single bucket "no proof endpoint
// answered" and the seventeen more specific buckets under it were unreachable for the one stage
// this project exists to measure. Nothing is lost by stripping it: the caller already keys the
// bucket by stage, so "proof: timed out" was "proof: no proof endpoint answered" saying the word
// proof twice and the condition never.
//
// It matters which one it was. A 403 over a verified chain means the node carried our traffic and
// the endpoint refused its IP; a timeout means the node carried nothing. A live sample of the
// published catalogue put 113 of 131 reached nodes in the first group, and the output could not
// say so.
func summariseReason(reason string) string {
	lower := strings.ToLower(reason)
	lower = strings.TrimPrefix(lower, proofWrapper)
	if lower == "" {
		return "no reason reported"
	}
	// Before the needles: a status code is more specific than any word in the message, and the
	// code itself is the actionable part. 429 keeps its established name because "rate limited"
	// is what an operator acts on.
	if m := statusRe.FindStringSubmatch(lower); m != nil {
		if m[1] == "429" {
			return "rate limited"
		}
		return "unexpected status " + m[1]
	}
	for _, probe := range []struct{ needle, bucket string }{
		{"certificate", "certificate verification failed"},
		{"tls", "tls handshake failed"},
		{"i/o timeout", "timed out"},
		{"deadline exceeded", "timed out"},
		{"timeout", "timed out"},
		{"context canceled", "cancelled"},
		{"connection refused", "connection refused"},
		{"connection reset", "connection reset"},
		{"no such host", "name does not resolve"},
		{"egress denied", "egress denied"},
		{"too many", "rate limited"},
		{"unreachable", "network unreachable"},
		{"forcibly closed", "connection reset"},
		{"wsarecv", "connection reset"},
		{"socket", "socket exhausted"},
	} {
		if strings.Contains(lower, probe.needle) {
			return probe.bucket
		}
	}
	// Anything that reaches here is a shape nobody anticipated, and it must not become one
	// bucket per node: that is how a list of failures stops being a summary. The address is
	// stripped and the tail kept, which is the part that names the condition.
	if i := strings.LastIndex(lower, ": "); i >= 0 && i+2 < len(lower) {
		return "unclassified: " + lower[i+2:]
	}
	if len(reason) > 60 {
		return reason[:60]
	}
	return reason
}
