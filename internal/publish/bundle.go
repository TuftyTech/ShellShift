package publish

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tuftytech/shellshift/internal/model"
)

// Bundle is one published subscription file.
type Bundle struct {
	// Name is the file name. Flat .txt names are used because GitHub Pages has no
	// rewrite engine and gives .txt the correct content type on its own; the pretty
	// paths of the predecessor were a feature of a different host (GHOST-039).
	Name string
	// Title goes in the profile header line.
	Title string
	// Include selects the nodes that belong in this bundle.
	Include func(model.Node) bool
}

// Bundles is the published set.
//
// The opaque names of the predecessor are gone: sub1 and sub2 told a visitor nothing, and
// the codenames told them less. There are no subscribers to preserve them for
// (GHOST-040).
//
// There is no complement of the whitelisted class here, and its absence is the decision.
// `sub_open.txt` was the set of nodes whose masking was *not* proven, which is a query
// nobody makes: a reader wants everything, or wants the subset with a proven disguise.
// What it did instead was collide with `sub_all.txt` — byte for byte identical whenever the
// whitelisted class was empty, which is every run where the whitelist feed fails to load —
// so the page offered two cards with the same count and the same contents and no way to
// tell that they were the same file twice. Dropping it rather than hiding it when the
// counts agree is what keeps a published URL from appearing and disappearing between runs.
func Bundles() []Bundle {
	return []Bundle{
		{"sub_all.txt", "ShellShift — all", func(model.Node) bool { return true }},
		{"sub_wl.txt", "ShellShift — whitelisted", func(n model.Node) bool {
			return n.Class == model.ClassWhitelisted
		}},
		{"sub_vless.txt", "ShellShift — vless", byProtocol(model.ProtoVLESS)},
		{"sub_vmess.txt", "ShellShift — vmess", byProtocol(model.ProtoVMess)},
		{"sub_trojan.txt", "ShellShift — trojan", byProtocol(model.ProtoTrojan)},
		{"sub_ss.txt", "ShellShift — shadowsocks", byProtocol(model.ProtoShadowsocks)},
		{"sub_hy2.txt", "ShellShift — hysteria2", byProtocol(model.ProtoHysteria2)},
	}
}

func byProtocol(p model.Protocol) func(model.Node) bool {
	return func(n model.Node) bool { return n.Identity.Protocol == p }
}

// Entry pairs a node with what was measured about it, which is what ranking needs.
type Entry struct {
	Node    model.Node
	Verdict model.Verdict
}

// ErrImplausible is returned when a result is too poor to publish over the previous one.
var ErrImplausible = errors.New("publish: result is implausible")

// Guard decides whether a result may replace what is already published.
//
// This is the counterpart to the predecessor single most damaging bug. There,
// merge_subscription_files opened every output file in write mode unconditionally, so a run
// in which all shards failed wrote two header lines over each of nine subscription files,
// committed them, and deployed. The only defence was a log line, and the
// "nothing changed, exit zero" check did not help because something had changed: the files
// had been emptied (INV-43).
type Guard struct {
	// MinNodes refuses a result below an absolute floor.
	MinNodes int
	// MinFractionOfPrevious refuses a result that collapses relative to the last one. A
	// catalogue of public proxies churns, so the threshold is generous; it is there to
	// catch a broken run, not a bad day.
	MinFractionOfPrevious float64
}

// DefaultGuard is deliberately permissive about churn and absolute about emptiness.
func DefaultGuard() Guard {
	return Guard{MinNodes: 1, MinFractionOfPrevious: 0.25}
}

// Check reports whether count nodes may be published given the previous count.
//
// A previous count of zero means nothing is published yet, so any non-empty result is an
// improvement and is allowed.
func (g Guard) Check(count, previous int) error {
	if count < g.MinNodes {
		return fmt.Errorf("%w: %d nodes, floor is %d", ErrImplausible, count, g.MinNodes)
	}
	if previous <= 0 {
		return nil
	}
	if g.MinFractionOfPrevious > 0 {
		floor := int(float64(previous) * g.MinFractionOfPrevious)
		if count < floor {
			return fmt.Errorf("%w: %d nodes against %d previously, floor is %d",
				ErrImplausible, count, previous, floor)
		}
	}
	return nil
}

// Render produces the body of one bundle.
//
// Ordering is global and deterministic. The predecessor sorted within each shard and then
// concatenated the shards in glob order, so its output was a sequence of sorted blocks
// that the team believed was globally sorted — and because the sort key was measured
// speed, line order changed on every run and delta compression was defeated.
func Render(b Bundle, entries []Entry, label func(Entry) string) (string, error) {
	selected := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if b.Include(e.Node) {
			selected = append(selected, e)
		}
	}

	sort.SliceStable(selected, func(i, j int) bool {
		li, lj := selected[i].Verdict.Measured.Latency, selected[j].Verdict.Measured.Latency
		if li != lj {
			// Unmeasured latency sorts last rather than first.
			if li == 0 {
				return false
			}
			if lj == 0 {
				return true
			}
			return li < lj
		}
		// The tie-break is the identity, which is stable across runs. Ranking by a
		// measured value alone reshuffles the file whenever the measurement wobbles.
		return selected[i].Node.Key() < selected[j].Node.Key()
	})

	var sb strings.Builder
	fmt.Fprintf(&sb, "#profile-title: %s\n", b.Title)
	fmt.Fprintf(&sb, "#profile-update-interval: %d\n", updateIntervalHours)

	for _, e := range selected {
		uri, err := Encode(e.Node, label(e))
		if err != nil {
			// One node that cannot be rendered must not lose the bundle. It is skipped
			// and the caller counts it; the predecessor emitted a bare "vmess://" line
			// in this situation, which a client reads as a broken entry.
			continue
		}
		sb.WriteString(uri)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// updateIntervalHours must match the real cadence. The predecessor published six while
// running every four hours (GHOST-024).
const updateIntervalHours = 4
