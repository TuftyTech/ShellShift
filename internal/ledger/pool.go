package ledger

import (
	"time"
)

// Entry is what the ledger remembers about one node.
//
// It holds no credential and no URI, only the identity hash. That is a deliberate
// narrowing of the predecessor design, which stored 1,232 full proxy URIs — other
// people's server credentials — in a file committed to a public repository on every run,
// including nodes that had stopped working. Publishing live nodes is the product;
// maintaining a durable, indexable archive of credentials for dead ones is not.
//
// The consequence is explicit: the ledger scores what the sources offer, it does not keep
// a node alive after every source has dropped it. Reviving a catalogue across a total
// source outage is a v1 non-goal, recorded as open question OQ-03.
type Entry struct {
	// ID is model.Identity.Key.
	ID string `json:"id"`
	// FirstSeen is when this identity first appeared in any source.
	FirstSeen time.Time `json:"first_seen"`
	// LastSeen is the most recent run in which a source offered it.
	LastSeen time.Time `json:"last_seen"`
	// LastProven is the most recent run in which it passed verification. The zero value
	// means it has never passed.
	LastProven time.Time `json:"last_proven,omitempty"`
	// Streak is the number of consecutive runs it has passed.
	Streak int `json:"streak,omitempty"`
	// Failures is the number of consecutive runs it has failed since last passing.
	Failures int `json:"failures,omitempty"`
	// NextCheck is the earliest run time at which it is worth spending a full
	// verification on again.
	NextCheck time.Time `json:"next_check,omitempty"`
	// Proofs and Attempts are lifetime totals, which is what makes a reliability figure
	// meaningful rather than a snapshot.
	Proofs   int `json:"proofs,omitempty"`
	Attempts int `json:"attempts,omitempty"`
}

// Reliability is the lifetime pass rate, or zero when nothing has been attempted.
func (e Entry) Reliability() float64 {
	if e.Attempts == 0 {
		return 0
	}
	return float64(e.Proofs) / float64(e.Attempts)
}

// Policy governs decay. Every value here answers something the predecessor got wrong.
type Policy struct {
	// BaseBackoff is the first delay applied after a failure.
	BaseBackoff time.Duration
	// MaxBackoff caps the delay so a node that recovers is eventually noticed.
	MaxBackoff time.Duration
	// MaxFailures evicts an entry after this many consecutive failures.
	MaxFailures int
	// MaxAge evicts an entry no source has offered for this long.
	//
	// The predecessor wrote a last_seen timestamp and never read it, so nothing ever aged
	// out: a node that squeaked through every third run lived forever, and thirty percent
	// of the pool was re-verified at full cost while failing.
	MaxAge time.Duration
}

// DefaultPolicy is tuned for a roughly two-hourly cadence.
//
// The backoff is wall-clock time rather than a count of runs, and it stayed at four hours when the
// cadence doubled: a node that has just failed sits out the next run, so the work spent on dead
// nodes per day is roughly what it was and the extra runs go to new and proven ones.
func DefaultPolicy() Policy {
	return Policy{
		BaseBackoff: 4 * time.Hour,
		MaxBackoff:  72 * time.Hour,
		MaxFailures: 8,
		MaxAge:      14 * 24 * time.Hour,
	}
}

// backoffFor returns the delay after n consecutive failures, doubling and capped.
func (p Policy) backoffFor(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := p.BaseBackoff
	for i := 1; i < failures && d < p.MaxBackoff; i++ {
		d *= 2
	}
	if d > p.MaxBackoff {
		d = p.MaxBackoff
	}
	return d
}
