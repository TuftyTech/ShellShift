package ledger

import (
	"sort"
	"time"
)

// SourceStat is the accumulated record for one feed.
//
// Counters are lifetime and both sides are counted on the *same* set. The predecessor
// recorded parsed from the full pre-shard parse and alive from one shard slice, which
// understated every yield by roughly four times — and every tuning retreat it documented
// was decided against those numbers (INV-42).
type SourceStat struct {
	// URL identifies the feed. It is stored in the clear because the source list is
	// public configuration, not a secret. The predecessor treated it as a secret while
	// committing all 118 of them to a public repository, which is the worst of both.
	URL string `json:"url"`

	Runs      int       `json:"runs,omitempty"`
	Offered   int       `json:"offered,omitempty"`
	Proven    int       `json:"proven,omitempty"`
	LastRun   time.Time `json:"last_run,omitempty"`
	LastProof time.Time `json:"last_proof,omitempty"`
	// Failures counts consecutive runs in which the feed could not be fetched at all,
	// which is a different thing from a feed returning nodes that do not work.
	Failures int `json:"failures,omitempty"`
}

// Yield is the lifetime proportion of offered nodes that were proven.
func (s SourceStat) Yield() float64 {
	if s.Offered == 0 {
		return 0
	}
	return float64(s.Proven) / float64(s.Offered)
}

// SourcePolicy governs when a feed stops being worth fetching.
type SourcePolicy struct {
	// MinRuns is how many runs a feed gets before its record counts against it.
	MinRuns int
	// RetireAfterBarrenRuns retires a feed that has produced nothing over this many runs.
	//
	// This replaces a 24-hour exclusion timer. Under that timer, 85 of 118 sources — none
	// of which had ever produced a single working node — returned roughly six times a day
	// forever and consumed 10.29 percent of all parse volume (GHOST-057).
	RetireAfterBarrenRuns int
	// RetireAfterFetchFailures retires a feed that cannot be fetched at all.
	RetireAfterFetchFailures int
}

// DefaultSourcePolicy is patient before retiring, and final afterwards.
func DefaultSourcePolicy() SourcePolicy {
	return SourcePolicy{
		MinRuns:                  6,
		RetireAfterBarrenRuns:    24,
		RetireAfterFetchFailures: 12,
	}
}

// Sources tracks feed performance.
type Sources struct {
	Policy SourcePolicy
	stats  map[string]*SourceStat
	now    func() time.Time
}

// NewSources builds an empty tracker.
func NewSources(policy SourcePolicy) *Sources {
	return &Sources{Policy: policy, stats: map[string]*SourceStat{}, now: time.Now}
}

// Stat returns a feed record.
func (s *Sources) Stat(url string) (SourceStat, bool) {
	st, ok := s.stats[url]
	if !ok {
		return SourceStat{}, false
	}
	return *st, true
}

// RecordRun records the outcome of fetching and verifying one feed.
//
// offered and proven must describe the same set of nodes. Passing a full parse count with
// a partial proven count is the exact mistake that made the predecessor telemetry unusable.
func (s *Sources) RecordRun(url string, offered, proven int) {
	now := s.now()
	st := s.ensure(url)
	st.Runs++
	st.Offered += offered
	st.Proven += proven
	st.LastRun = now
	st.Failures = 0
	if proven > 0 {
		st.LastProof = now
	}
}

// RecordFetchFailure records that a feed could not be retrieved.
func (s *Sources) RecordFetchFailure(url string) {
	st := s.ensure(url)
	st.Runs++
	st.Failures++
	st.LastRun = s.now()
}

func (s *Sources) ensure(url string) *SourceStat {
	st, ok := s.stats[url]
	if !ok {
		st = &SourceStat{URL: url}
		s.stats[url] = st
	}
	return st
}

// Retired reports whether a feed has earned removal from the rotation.
func (s *Sources) Retired(url string) (bool, string) {
	st, ok := s.stats[url]
	if !ok {
		return false, ""
	}
	if s.Policy.RetireAfterFetchFailures > 0 && st.Failures >= s.Policy.RetireAfterFetchFailures {
		return true, "cannot be fetched"
	}
	if st.Runs < s.Policy.MinRuns {
		return false, ""
	}
	if s.Policy.RetireAfterBarrenRuns > 0 &&
		st.Runs >= s.Policy.RetireAfterBarrenRuns && st.Proven == 0 {
		return true, "has never produced a working node"
	}
	return false, ""
}

// Ranked returns the active feeds ordered by descending yield.
//
// Order is what a scheduler acts on: in the observed corpus one feed produced 48 percent
// of all working nodes from 3 percent of the parse volume, while three high-volume feeds
// produced almost nothing from most of it. Treating all feeds equally spends the run
// budget in inverse proportion to value.
func (s *Sources) Ranked() []SourceStat {
	out := make([]SourceStat, 0, len(s.stats))
	for url, st := range s.stats {
		if retired, _ := s.Retired(url); retired {
			continue
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		yi, yj := out[i].Yield(), out[j].Yield()
		if yi != yj {
			return yi > yj
		}
		if out[i].Proven != out[j].Proven {
			return out[i].Proven > out[j].Proven
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// All returns every record, sorted by URL for byte-stable output.
func (s *Sources) All() []SourceStat {
	out := make([]SourceStat, 0, len(s.stats))
	for _, st := range s.stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}
