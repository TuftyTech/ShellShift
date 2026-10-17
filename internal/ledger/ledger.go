package ledger

import (
	"encoding/json"
	"io"
	"sort"
	"time"
)

// Ledger is the memory of the system.
type Ledger struct {
	Policy  Policy
	entries map[string]*Entry
	now     func() time.Time
}

// New builds an empty ledger.
func New(policy Policy) *Ledger {
	return &Ledger{Policy: policy, entries: map[string]*Entry{}, now: time.Now}
}

// Len is the number of entries.
func (l *Ledger) Len() int { return len(l.entries) }

// Get returns an entry and whether it exists.
func (l *Ledger) Get(id string) (Entry, bool) {
	e, ok := l.entries[id]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Observe records that a source offered this identity in the current run.
func (l *Ledger) Observe(id string) {
	now := l.now()
	e, ok := l.entries[id]
	if !ok {
		l.entries[id] = &Entry{ID: id, FirstSeen: now, LastSeen: now}
		return
	}
	e.LastSeen = now
}

// RecordProof records a successful verification.
func (l *Ledger) RecordProof(id string) {
	now := l.now()
	e := l.ensure(id, now)
	e.LastProven = now
	e.Streak++
	e.Failures = 0
	e.Proofs++
	e.Attempts++
	// A node that just passed is worth checking again next run: freshness is the product.
	e.NextCheck = time.Time{}
}

// RecordFailure records a failed verification and pushes the next check out.
func (l *Ledger) RecordFailure(id string) {
	now := l.now()
	e := l.ensure(id, now)
	e.Streak = 0
	e.Failures++
	e.Attempts++
	e.NextCheck = now.Add(l.Policy.backoffFor(e.Failures))
}

// DueForCheck reports whether a full verification is worth spending now.
//
// An entry the ledger has never seen is always due: a new node must be tried. An entry in
// backoff is not, and that is the mechanism the predecessor lacked — it re-verified every
// pooled node at full cost every run, including the three hundred and sixty-seven that
// had been failing for one or two runs already.
func (l *Ledger) DueForCheck(id string) bool {
	e, ok := l.entries[id]
	if !ok {
		return true
	}
	if e.NextCheck.IsZero() {
		return true
	}
	return !l.now().Before(e.NextCheck)
}

// Prune removes entries that have decayed, returning how many went and why.
func (l *Ledger) Prune() (byFailures, byAge int) {
	now := l.now()
	for id, e := range l.entries {
		switch {
		case l.Policy.MaxFailures > 0 && e.Failures >= l.Policy.MaxFailures:
			delete(l.entries, id)
			byFailures++
		case l.Policy.MaxAge > 0 && !e.LastSeen.IsZero() && now.Sub(e.LastSeen) > l.Policy.MaxAge:
			delete(l.entries, id)
			byAge++
		}
	}
	return byFailures, byAge
}

// Entries returns a stable, sorted snapshot.
//
// Sorting matters beyond tidiness: the published state must be byte-stable under
// regeneration from unchanged inputs, or every run produces a diff for no reason
// (PERF-041).
func (l *Ledger) Entries() []Entry {
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (l *Ledger) ensure(id string, now time.Time) *Entry {
	e, ok := l.entries[id]
	if !ok {
		e = &Entry{ID: id, FirstSeen: now, LastSeen: now}
		l.entries[id] = e
	}
	return e
}

// snapshot is the on-disk shape, versioned so a format change is detectable rather than
// silently misread.
type snapshot struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

const snapshotVersion = 1

// Save writes the ledger.
func (l *Ledger) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(snapshot{Version: snapshotVersion, Entries: l.Entries()})
}

// Load reads a ledger. A missing or unreadable file is the caller's decision to treat as
// empty; a file in an unknown version is an error, because guessing at it would corrupt
// the reputation data the scheduler depends on.
func Load(r io.Reader, policy Policy) (*Ledger, error) {
	var s snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, err
	}
	if s.Version != snapshotVersion {
		return nil, &VersionError{Got: s.Version, Want: snapshotVersion}
	}
	l := New(policy)
	for i := range s.Entries {
		e := s.Entries[i]
		l.entries[e.ID] = &e
	}
	return l, nil
}

// VersionError reports an unreadable snapshot format.
type VersionError struct{ Got, Want int }

func (e *VersionError) Error() string {
	return "ledger: snapshot version " + itoa(e.Got) + ", want " + itoa(e.Want)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
