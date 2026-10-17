package ledger

import (
	"bytes"
	"testing"
	"time"
)

func fixedLedger(t *testing.T) (*Ledger, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	l := New(DefaultPolicy())
	l.now = func() time.Time { return now }
	return l, &now
}

// A node that has never been seen is always worth trying.
func TestUnknownNodeIsDue(t *testing.T) {
	l, _ := fixedLedger(t)
	if !l.DueForCheck("unknown") {
		t.Fatal("an unknown identity must be due for a check")
	}
}

// A node that just passed is due again immediately: freshness is the product.
func TestProvenNodeIsDueAgain(t *testing.T) {
	l, _ := fixedLedger(t)
	l.Observe("a")
	l.RecordProof("a")
	if !l.DueForCheck("a") {
		t.Fatal("a node that just passed must be re-checked next run")
	}
	e, _ := l.Get("a")
	if e.Streak != 1 || e.Failures != 0 || e.Proofs != 1 || e.Attempts != 1 {
		t.Fatalf("entry = %+v", e)
	}
}

// The mechanism the predecessor lacked: it re-verified every pooled node at full cost
// every run, including the 367 of 1,232 that had already been failing.
func TestFailureBacksOffExponentially(t *testing.T) {
	l, now := fixedLedger(t)
	l.Observe("a")

	var delays []time.Duration
	for i := 1; i <= 5; i++ {
		l.RecordFailure("a")
		e, _ := l.Get("a")
		delays = append(delays, e.NextCheck.Sub(*now))
		if l.DueForCheck("a") {
			t.Fatalf("after %d failures the node must not be due immediately", i)
		}
	}

	for i := 1; i < len(delays); i++ {
		if delays[i] <= delays[i-1] && delays[i] < DefaultPolicy().MaxBackoff {
			t.Fatalf("delay %d (%v) did not grow past %v", i, delays[i], delays[i-1])
		}
	}
	if last := delays[len(delays)-1]; last > DefaultPolicy().MaxBackoff {
		t.Fatalf("delay %v exceeded the cap %v", last, DefaultPolicy().MaxBackoff)
	}
}

// Time moving past the backoff makes the node due again, so a node that recovers is
// eventually noticed.
func TestBackoffExpires(t *testing.T) {
	l, now := fixedLedger(t)
	l.Observe("a")
	l.RecordFailure("a")
	if l.DueForCheck("a") {
		t.Fatal("should be in backoff")
	}
	*now = now.Add(DefaultPolicy().MaxBackoff + time.Hour)
	if !l.DueForCheck("a") {
		t.Fatal("backoff must expire")
	}
}

// A success resets the backoff entirely.
func TestProofResetsFailures(t *testing.T) {
	l, _ := fixedLedger(t)
	l.Observe("a")
	l.RecordFailure("a")
	l.RecordFailure("a")
	l.RecordProof("a")

	e, _ := l.Get("a")
	if e.Failures != 0 {
		t.Fatalf("failures = %d, want 0", e.Failures)
	}
	if !l.DueForCheck("a") {
		t.Fatal("a recovered node must be due again")
	}
}

// Eviction by consecutive failures.
func TestPruneByFailures(t *testing.T) {
	l, _ := fixedLedger(t)
	l.Observe("a")
	for i := 0; i < DefaultPolicy().MaxFailures; i++ {
		l.RecordFailure("a")
	}
	byFail, byAge := l.Prune()
	if byFail != 1 || byAge != 0 {
		t.Fatalf("pruned byFailures=%d byAge=%d, want 1 and 0", byFail, byAge)
	}
	if _, ok := l.Get("a"); ok {
		t.Fatal("the entry should be gone")
	}
}

// Eviction by age. The predecessor wrote a last_seen timestamp and never read it, so a
// node that squeaked through every third run lived forever.
func TestPruneByAge(t *testing.T) {
	l, now := fixedLedger(t)
	l.Observe("stale")
	l.RecordProof("stale")

	*now = now.Add(DefaultPolicy().MaxAge + time.Hour)
	l.Observe("fresh")

	byFail, byAge := l.Prune()
	if byAge != 1 || byFail != 0 {
		t.Fatalf("pruned byFailures=%d byAge=%d, want 0 and 1", byFail, byAge)
	}
	if _, ok := l.Get("fresh"); !ok {
		t.Fatal("the fresh entry must survive")
	}
}

func TestReliabilityIsLifetime(t *testing.T) {
	l, _ := fixedLedger(t)
	l.Observe("a")
	l.RecordProof("a")
	l.RecordFailure("a")
	l.RecordProof("a")
	e, _ := l.Get("a")
	if got := e.Reliability(); got < 0.66 || got > 0.67 {
		t.Fatalf("reliability = %v, want about 2/3", got)
	}
	var empty Entry
	if empty.Reliability() != 0 {
		t.Fatal("an entry with no attempts must report zero, not divide by zero")
	}
}

// PERF-041. Published state must be byte-stable under regeneration from unchanged inputs,
// or every run produces a diff for no reason.
func TestSnapshotIsByteStable(t *testing.T) {
	l, _ := fixedLedger(t)
	for _, id := range []string{"ccc", "aaa", "bbb"} {
		l.Observe(id)
		l.RecordProof(id)
	}

	var first, second bytes.Buffer
	if err := l.Save(&first); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := l.Save(&second); err != nil {
		t.Fatalf("save: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("two saves of the same state produced different bytes")
	}

	loaded, err := Load(bytes.NewReader(first.Bytes()), DefaultPolicy())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var round bytes.Buffer
	if err := loaded.Save(&round); err != nil {
		t.Fatalf("save after load: %v", err)
	}
	if round.String() != first.String() {
		t.Fatal("a save/load/save round trip changed the bytes")
	}
}

// A snapshot in an unknown version is an error. Guessing would corrupt the reputation
// data the scheduler depends on.
func TestUnknownSnapshotVersionIsAnError(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte(`{"version":99,"entries":[]}`)), DefaultPolicy())
	if err == nil {
		t.Fatal("an unknown version must be refused")
	}
	var ve *VersionError
	if !asVersionError(err, &ve) {
		t.Fatalf("error = %v, want a VersionError", err)
	}
}

// INV-22. The ledger holds no credential and no URI, only the identity hash. Publishing live
// nodes is the product; keeping a durable archive of other people's credentials is not.
//
// Keying the pool by the published URI is what the predecessor did, and its fragment carried a
// GeoIP flag and country name: one GeoIP flip renamed the node and split the record. Measured,
// that was 1,232 pool entries against 865 published nodes.
func TestSnapshotCarriesNoCredentials(t *testing.T) {
	l, _ := fixedLedger(t)
	l.Observe("3f2a1b0c")
	l.RecordProof("3f2a1b0c")

	var buf bytes.Buffer
	if err := l.Save(&buf); err != nil {
		t.Fatalf("save: %v", err)
	}
	for _, forbidden := range []string{"://", "vless", "@", "password", "uuid"} {
		if bytes.Contains(buf.Bytes(), []byte(forbidden)) {
			t.Fatalf("snapshot contains %q:\n%s", forbidden, buf.String())
		}
	}
}

func asVersionError(err error, target **VersionError) bool {
	if e, ok := err.(*VersionError); ok {
		*target = e
		return true
	}
	return false
}
