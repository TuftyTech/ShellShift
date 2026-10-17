package verify

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/policy"
	"github.com/tuftytech/shellshift/internal/tunnel"
)

// Budget bounds what one node may cost.
//
// Every value here exists because the predecessor spent roughly eighty percent of its
// wall-clock waiting on nodes that were never going to pass: a fixed four-second DNS
// timeout, an eight-second dial, an unconditional two-second sleep, a ten-second retry,
// and then two connectivity URLs tried one after the other at seven seconds each. That
// is twenty-four seconds of L4 and fourteen of L7 for a node that fails, multiplied by
// the ninety-nine percent of candidates that do.
type Budget struct {
	// Resolve bounds name resolution.
	Resolve time.Duration
	// Reach bounds the plain TCP reachability probe. It is deliberately short: a live
	// proxy completes a TCP handshake well inside a second, and waiting longer only
	// makes dead nodes cost more.
	Reach time.Duration
	// Proof bounds the end-to-end request through the tunnel, including the TLS
	// handshake to the destination.
	Proof time.Duration
	// Throughput bounds the measurement pass.
	Throughput time.Duration
	// Total is the hard ceiling for one node across all stages.
	Total time.Duration
}

// DefaultBudget is tuned for the observation that failure is the common case.
func DefaultBudget() Budget {
	return Budget{
		Resolve:    2 * time.Second,
		Reach:      1500 * time.Millisecond,
		Proof:      6 * time.Second,
		Throughput: 8 * time.Second,
		Total:      15 * time.Second,
	}
}

// AddressResolver turns a hostname into one vetted address. It is an interface so a run
// can put a per-run cache in front of the real resolver: measured on a live feed, half of
// all resolution is duplicated because 13,242 nodes carried only 6,574 distinct hostnames.
type AddressResolver interface {
	Resolve(ctx context.Context, host string) (netip.Addr, error)
}

// Engine verifies nodes.
type Engine struct {
	Resolver AddressResolver
	Dialer   tunnel.Dialer
	Prover   *Prover
	// Meter measures throughput. It is optional: a nil meter means the stage is skipped and
	// recorded as skipped, which is different from measuring zero.
	Meter  *Meter
	Budget Budget

	// SkipReach disables the plain TCP pre-check. It exists for tests and for the case
	// where a caller already knows the endpoint answers.
	SkipReach bool

	// proofSlots bounds how many proofs run at once, independently of how many verifications
	// run at once.
	//
	// The two stages scale in opposite directions and one limit cannot serve both. Reach is a
	// plain TCP dial to a distinct node, so nothing is shared and the only ceiling is our own
	// sockets — at 100k candidates it wants thousands in flight. Proof goes through a tunnel to
	// three or eight *shared* endpoints, and that sharing is the whole reason a run starts
	// collecting 429s: one limit set high enough for reach points thousands of simultaneous
	// requests at three providers, and INV-53 already measured what that does to the yield.
	//
	// Modelled on the live run, whose timings this reproduces within 5%: at 100k candidates a
	// single limit of 256 needs 15.4 minutes against a 6-minute budget, of which 400 seconds is
	// reach waiting on timeouts it could have done thousands at a time.
	proofSlots chan struct{}
	// now is injectable so a test can assert timing without waiting for it.
	now func() time.Time
}

// LimitProofs bounds simultaneous proofs. Zero or less removes the bound.
//
// It is separate from the scheduler the caller uses because the caller's limit governs how many
// nodes are in flight, and most of those are in a stage that costs a third party nothing.
func (e *Engine) LimitProofs(n int) {
	if n <= 0 {
		e.proofSlots = nil
		return
	}
	e.proofSlots = make(chan struct{}, n)
}

// acquireProof takes a proof slot, or reports that the context ended first.
func (e *Engine) acquireProof(ctx context.Context) error {
	if e.proofSlots == nil {
		return nil
	}
	select {
	case e.proofSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) releaseProof() {
	if e.proofSlots != nil {
		<-e.proofSlots
	}
}

// New builds an engine with the default budget.
func New(dialer tunnel.Dialer, prover *Prover) *Engine {
	return &Engine{
		Resolver: policy.NewCachingResolver(policy.NewResolver(), 5*time.Minute),
		Dialer:   dialer,
		Prover:   prover,
		Budget:   DefaultBudget(),
		now:      time.Now,
	}
}

func (e *Engine) clock() func() time.Time {
	if e.now != nil {
		return e.now
	}
	return time.Now
}

// Verify runs a node through the pipeline and returns what was proven.
//
// Stages are recorded individually rather than collapsed into one counter. The
// predecessor added translation rejects, real reachability failures and end-to-end
// losses into a single number that the dashboard then labelled as an L4 figure, and every
// tuning decision it made rested on that number (INV-41).
func (e *Engine) Verify(ctx context.Context, node model.Node) model.Verdict {
	now := e.clock()
	v := model.Verdict{Identity: node.Key(), At: now()}

	ctx, cancel := context.WithTimeout(ctx, e.Budget.Total)
	defer cancel()

	// --- resolve and vet ------------------------------------------------------
	start := now()
	resolveCtx, cancelResolve := context.WithTimeout(ctx, e.Budget.Resolve)
	addr, err := e.Resolver.Resolve(resolveCtx, node.Identity.Server)
	cancelResolve()
	if err != nil {
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StagePolicy, Outcome: model.OutcomeFail,
			Reason: err.Error(), Elapsed: now().Sub(start),
		})
		return v
	}
	// The resolver vetted the address on its own terms. This is the part of the judgement that
	// needs the node: a bare TCP or QUIC endpoint inside a CDN or public-resolver range is not
	// something a CDN could be carrying, because a CDN terminates HTTP (INV-34).
	if err := policy.VetNodeAddr(node, addr); err != nil {
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StagePolicy, Outcome: model.OutcomeFail,
			Reason: err.Error(), Elapsed: now().Sub(start),
		})
		return v
	}
	v.Stages = append(v.Stages, model.StageResult{
		Stage: model.StagePolicy, Outcome: model.OutcomePass, Elapsed: now().Sub(start),
	})

	target := tunnel.Target{Node: node, Server: addr}

	// --- cheap reachability ---------------------------------------------------
	// A UDP protocol has no TCP handshake to probe, so the stage is skipped rather than
	// silently reported as a pass. The predecessor returned early from the whole check
	// for these protocols, which also skipped address vetting (INV-33).
	if e.SkipReach || node.Identity.Protocol.UsesUDP() {
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StageReach, Outcome: model.OutcomeSkipped,
			Reason: "protocol carries no TCP handshake",
		})
	} else {
		start = now()
		if err := e.reach(ctx, addr, node.Identity.Port); err != nil {
			v.Stages = append(v.Stages, model.StageResult{
				Stage: model.StageReach, Outcome: model.OutcomeFail,
				Reason: err.Error(), Elapsed: now().Sub(start),
			})
			return v
		}
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StageReach, Outcome: model.OutcomePass, Elapsed: now().Sub(start),
		})
	}

	// --- proof ----------------------------------------------------------------
	// Bounded separately from the caller's concurrency: this is the stage that touches shared
	// third parties, and the wait is deliberately outside the stage clock so that queueing for a
	// slot is not recorded as the node being slow.
	if err := e.acquireProof(ctx); err != nil {
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StageProof, Outcome: model.OutcomeFail,
			Reason: "run budget ended while queued for a proof slot",
		})
		return v
	}
	start = now()
	proofCtx, cancelProof := context.WithTimeout(ctx, e.Budget.Proof)
	result, err := e.Prover.Prove(proofCtx, e.Dialer, target)
	cancelProof()
	e.releaseProof()
	elapsed := now().Sub(start)
	if err != nil {
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StageProof, Outcome: model.OutcomeFail,
			Reason: err.Error(), Elapsed: elapsed,
		})
		return v
	}
	v.Stages = append(v.Stages, model.StageResult{
		Stage: model.StageProof, Outcome: model.OutcomePass, Elapsed: elapsed,
	})
	v.Measured.Latency = result.Latency

	// Surviving the proof is what keeps a node. Everything below is ranking information, and
	// none of it can eliminate one (INV-37, GHOST-020).
	v.Proven = true

	// --- throughput -----------------------------------------------------------
	if e.Meter == nil {
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StageThroughput, Outcome: model.OutcomeSkipped,
			Reason: "no meter configured",
		})
		return v
	}

	start = now()
	meterCtx, cancelMeter := context.WithTimeout(ctx, e.Budget.Throughput)
	mbps, bytes, err := e.Meter.Measure(meterCtx, e.Dialer, target)
	cancelMeter()
	elapsed = now().Sub(start)

	if err != nil {
		// A failed measurement records nothing rather than a zero. A zero published as a
		// measurement reads as a slow node, and the node is not slow: it is unmeasured
		// (INV-36).
		v.Stages = append(v.Stages, model.StageResult{
			Stage: model.StageThroughput, Outcome: model.OutcomeFail,
			Reason: err.Error(), Elapsed: elapsed,
		})
		return v
	}
	v.Stages = append(v.Stages, model.StageResult{
		Stage: model.StageThroughput, Outcome: model.OutcomePass, Elapsed: elapsed,
	})
	v.Measured.Mbps = mbps
	v.Measured.Bytes = bytes
	return v
}

// reach opens and immediately closes a TCP connection to the endpoint.
func (e *Engine) reach(ctx context.Context, addr netip.Addr, port uint16) error {
	ctx, cancel := context.WithTimeout(ctx, e.Budget.Reach)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	return conn.Close()
}
