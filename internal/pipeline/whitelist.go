package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/tuftytech/shellshift/internal/intake"
	"github.com/tuftytech/shellshift/internal/policy"
)

// LoadWhitelist fetches the censor whitelist feeds.
//
// Domains and networks degrade independently, and a partial load is still useful: losing the
// network feed should not cost the domain matches. That independence is carried over from the
// predecessor, which cached each category separately for the same reason (INV-32).
//
// What is not carried over is silence. An empty whitelist there meant every node quietly became
// the open class, with a log line nobody read. Here the failures come back to the caller so the
// run can say why a class is small.
func LoadWhitelist(ctx context.Context, f *intake.Fetcher, domains, networks []string) (*policy.Whitelist, []string) {
	// These feeds are lists of names and networks, not proxy links, so the reader is told to
	// take them as plain lines rather than looking for a wrapped feed inside them.
	plain := *f
	plain.Limits.PlainLines = true
	f = &plain

	wl := policy.NewWhitelist()
	var problems []string

	for _, url := range domains {
		body, err := f.Fetch(ctx, url)
		if err != nil {
			problems = append(problems, fmt.Sprintf("domain feed %s: %v", url, err))
			continue
		}
		if body.Truncated {
			problems = append(problems, fmt.Sprintf(
				"domain feed %s: cut at the %d-line cap, the rest of the list was not read",
				url, f.Limits.MaxNodesPerSource))
		}
		if _, err := wl.AddDomains(strings.NewReader(strings.Join(body.Lines, "\n"))); err != nil {
			problems = append(problems, fmt.Sprintf("domain feed %s: %v", url, err))
		}
	}

	for _, url := range networks {
		body, err := f.Fetch(ctx, url)
		if err != nil {
			problems = append(problems, fmt.Sprintf("network feed %s: %v", url, err))
			continue
		}
		// A truncated whitelist under-classifies silently, which is the shape of failure this
		// package exists to refuse. The intake reader has recorded the cut since it was
		// written and nothing here looked: on a live run the CIDR feed came back with exactly
		// 50 000 lines — the cap, to the line — and the report said only how many entries had
		// loaded, which is the number that looks fine.
		if body.Truncated {
			problems = append(problems, fmt.Sprintf(
				"network feed %s: cut at the %d-line cap, the rest of the list was not read",
				url, f.Limits.MaxNodesPerSource))
		}
		if _, err := wl.AddNetworks(strings.NewReader(strings.Join(body.Lines, "\n"))); err != nil {
			problems = append(problems, fmt.Sprintf("network feed %s: %v", url, err))
		}
	}

	return wl, problems
}
