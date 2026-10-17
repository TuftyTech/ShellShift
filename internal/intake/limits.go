package intake

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// Limits bound what one source may cost.
//
// The predecessor read remote bodies with no cap at all: aiohttp inflated gzip
// transparently, fifteen sources were fetched concurrently, and a single oversized or
// highly compressible response could take a shard out of a run — after which
// git pull --rebase || true kept the pipeline green and stale subscriptions were served
// (SEC-003).
type Limits struct {
	// MaxBytes caps the compressed body.
	MaxBytes int64
	// MaxDecodedBytes caps what a decompressed body may expand to. A response can be
	// small on the wire and enormous in memory.
	MaxDecodedBytes int64
	// MaxLineBytes caps one line. A feed with no newlines is not a feed.
	MaxLineBytes int
	// MaxNodesPerSource caps how much one feed may contribute, so a single source cannot
	// dominate a run by volume alone.
	MaxNodesPerSource int
	// PerSource is the wall-clock budget for one source including retries.
	PerSource time.Duration
	// MaxRedirects caps redirect hops. Each hop is vetted independently.
	MaxRedirects int

	// PlainLines reads the body as lines without trying to recognise a base64-wrapped feed.
	//
	// It exists for the whitelist feeds, which are lists of domains and networks and therefore
	// contain no protocol links at all. Without it the reader sees a body with nothing
	// recognisable in it and tries to decode the whole thing, which is the wrong question to
	// ask of a list of hostnames.
	PlainLines bool
}

// DefaultLimits are sized from the observed corpus: the largest real feed contributed
// about 130,000 parsed lines, and the whole run parsed roughly 65,000 nodes.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:          32 << 20, // 32 MiB
		MaxDecodedBytes:   96 << 20, // 96 MiB
		MaxLineBytes:      8 << 10,  // 8 KiB
		MaxNodesPerSource: 50_000,
		PerSource:         25 * time.Second,
		MaxRedirects:      3,
	}
}

// ErrLimitExceeded is returned when a body outgrows its allowance.
var ErrLimitExceeded = errors.New("intake: limit exceeded")

// limitedReader fails instead of truncating.
//
// Truncating would be worse than failing: a half-read feed parses into a plausible but
// arbitrary subset, and the run would look successful while quietly dropping nodes.
type limitedReader struct {
	r     io.Reader
	left  int64
	what  string
	limit int64
}

func newLimitedReader(r io.Reader, limit int64, what string) *limitedReader {
	return &limitedReader{r: r, left: limit, what: what, limit: limit}
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, fmt.Errorf("%w: %s over %d bytes", ErrLimitExceeded, l.what, l.limit)
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
