package ledger

import (
	"testing"
	"time"
)

func fixedSources(t *testing.T) *Sources {
	t.Helper()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	s := NewSources(DefaultSourcePolicy())
	s.now = func() time.Time { return now }
	return s
}

// A new feed is always tried: a record that does not exist yet cannot count against it.
func TestNewSourceIsNotRetired(t *testing.T) {
	s := fixedSources(t)
	const url = "https://example.com/a.txt"
	if retired, _ := s.Retired(url); retired {
		t.Fatal("an unknown feed must not be retired")
	}
	s.RecordRun(url, 100, 0)
	if retired, _ := s.Retired(url); retired {
		t.Fatal("one barren run must not retire a feed")
	}
}

// This replaces a 24-hour timer under which 85 of 118 feeds that had never produced a
// working node returned roughly six times a day forever, consuming 10.29 percent of all
// parse volume (GHOST-057).
func TestBarrenSourceIsRetiredByAccumulatedEvidence(t *testing.T) {
	s := fixedSources(t)
	const url = "https://example.com/barren.txt"
	p := DefaultSourcePolicy()

	for i := 0; i < p.RetireAfterBarrenRuns-1; i++ {
		s.RecordRun(url, 500, 0)
	}
	if retired, _ := s.Retired(url); retired {
		t.Fatalf("retired too early, threshold is %d runs", p.RetireAfterBarrenRuns)
	}
	s.RecordRun(url, 500, 0)
	retired, why := s.Retired(url)
	if !retired {
		t.Fatal("a feed with no proven node over the threshold must be retired")
	}
	if why == "" {
		t.Fatal("retirement must carry a reason")
	}
}

// A feed that produces even a little is kept, however large its volume.
func TestProductiveSourceIsNeverRetiredForVolume(t *testing.T) {
	s := fixedSources(t)
	const url = "https://example.com/firehose.txt"
	for i := 0; i < 100; i++ {
		s.RecordRun(url, 30000, 2)
	}
	if retired, _ := s.Retired(url); retired {
		t.Fatal("a feed that produces working nodes must not be retired")
	}
}

// An unfetchable feed is a different failure from one returning nodes that do not work.
func TestUnfetchableSourceIsRetiredSeparately(t *testing.T) {
	s := fixedSources(t)
	const url = "https://gone.example.com/a.txt"
	for i := 0; i < DefaultSourcePolicy().RetireAfterFetchFailures; i++ {
		s.RecordFetchFailure(url)
	}
	retired, why := s.Retired(url)
	if !retired {
		t.Fatal("a feed that cannot be fetched must be retired")
	}
	if why != "cannot be fetched" {
		t.Fatalf("reason = %q", why)
	}
}

func TestSuccessfulFetchClearsFailureStreak(t *testing.T) {
	s := fixedSources(t)
	const url = "https://flaky.example.com/a.txt"
	for i := 0; i < 5; i++ {
		s.RecordFetchFailure(url)
	}
	s.RecordRun(url, 10, 1)
	st, _ := s.Stat(url)
	if st.Failures != 0 {
		t.Fatalf("failures = %d, want 0", st.Failures)
	}
}

// Order is what a scheduler acts on. In the observed corpus one feed produced 48 percent
// of all working nodes from 3 percent of the parse volume.
func TestRankedOrdersByYieldNotVolume(t *testing.T) {
	s := fixedSources(t)
	s.RecordRun("https://example.com/precise.txt", 175, 21)
	s.RecordRun("https://example.com/good.txt", 9758, 639)
	s.RecordRun("https://example.com/firehose.txt", 130755, 197)

	ranked := s.Ranked()
	if len(ranked) != 3 {
		t.Fatalf("got %d feeds", len(ranked))
	}
	if ranked[0].URL != "https://example.com/precise.txt" {
		t.Fatalf("first = %s, want the highest-yield feed", ranked[0].URL)
	}
	if ranked[2].URL != "https://example.com/firehose.txt" {
		t.Fatalf("last = %s, want the firehose", ranked[2].URL)
	}
}

// Retired feeds disappear from the rotation, but their record stays auditable.
func TestRankedExcludesRetired(t *testing.T) {
	s := fixedSources(t)
	const dead = "https://example.com/dead.txt"
	for i := 0; i < DefaultSourcePolicy().RetireAfterBarrenRuns; i++ {
		s.RecordRun(dead, 1000, 0)
	}
	s.RecordRun("https://example.com/live.txt", 100, 10)

	ranked := s.Ranked()
	if len(ranked) != 1 || ranked[0].URL != "https://example.com/live.txt" {
		t.Fatalf("ranked = %+v", ranked)
	}
	if _, ok := s.Stat(dead); !ok {
		t.Fatal("the retired record must remain readable")
	}
}

func TestYieldOfEmptyRecordIsZero(t *testing.T) {
	var st SourceStat
	if st.Yield() != 0 {
		t.Fatal("an empty record must report zero rather than divide by zero")
	}
}
