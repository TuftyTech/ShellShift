package publish

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/model"
)

func entry(t *testing.T, uri string, latency time.Duration, class model.Class) Entry {
	t.Helper()
	res, err := decode.Decode(uri)
	if err != nil {
		t.Fatalf("decode %q: %v", uri, err)
	}
	n := res.Node
	n.Class = class
	return Entry{
		Node: n,
		Verdict: model.Verdict{
			Identity: n.Key(),
			Proven:   true,
			Measured: model.Measurement{Latency: latency},
		},
	}
}

func sample(t *testing.T) []Entry {
	t.Helper()
	return []Entry{
		entry(t, "vless://"+uuid+"@a.example.com:443?type=tcp&security=reality&pbk="+pbk, 300*time.Millisecond, model.ClassWhitelisted),
		entry(t, "vless://"+uuid+"@b.example.com:443?type=ws&security=tls&path=%2Fw", 100*time.Millisecond, model.ClassOpen),
		entry(t, "trojan://p4ss@c.example.com:443?security=tls", 200*time.Millisecond, model.ClassOpen),
		entry(t, "ss://aes-256-gcm:pw@d.example.com:8388", 0, model.ClassOpen),
	}
}

// The counterpart to the predecessor most damaging bug: a run in which every shard failed
// wrote two header lines over each of nine subscription files, committed them, and
// deployed. Every user subscription became empty (INV-43).
func TestGuardRefusesAnEmptyResult(t *testing.T) {
	g := DefaultGuard()
	if err := g.Check(0, 865); !errors.Is(err, ErrImplausible) {
		t.Fatalf("error = %v, want an implausibility refusal", err)
	}
	if err := g.Check(0, 0); !errors.Is(err, ErrImplausible) {
		t.Fatal("an empty result must be refused even with nothing published before")
	}
}

// A collapse relative to the previous run is refused. The threshold is generous because a
// catalogue of public proxies churns; it exists to catch a broken run, not a bad day.
func TestGuardRefusesACollapse(t *testing.T) {
	g := DefaultGuard()
	if err := g.Check(100, 865); !errors.Is(err, ErrImplausible) {
		t.Fatalf("a drop from 865 to 100 should be refused, got %v", err)
	}
	if err := g.Check(600, 865); err != nil {
		t.Fatalf("ordinary churn must be allowed, got %v", err)
	}
	if err := g.Check(900, 865); err != nil {
		t.Fatalf("growth must be allowed, got %v", err)
	}
}

// The first run has nothing to compare against, so any non-empty result is an improvement.
func TestGuardAllowsTheFirstPublication(t *testing.T) {
	if err := DefaultGuard().Check(3, 0); err != nil {
		t.Fatalf("the first publication must be allowed, got %v", err)
	}
}

// INV-45. A bundle that nothing qualified for must still render. Its absence must not fail the
// publication of everything else.
//
// The predecessor's shape of this was a hard `git add a b c` returning exit 1 when any one path
// did not exist — sub_ru.txt, when the RU probe found nothing — and that took down the whole
// merge job, losing the eight bundles that were fine. ShellShift commits no artifacts at all,
// so the mechanism is gone, but the rule it was breaking is the one under test: an empty
// optional output is an empty output, not an error.
func TestAnEmptyBundleStillRenders(t *testing.T) {
	// The sample carries no Hysteria2 node, so its bundle selects nothing.
	entries := sample(t)
	var hy2 Bundle
	for _, b := range Bundles() {
		if b.Name == "sub_hy2.txt" {
			hy2 = b
		}
	}
	if hy2.Name == "" {
		t.Fatal("no hysteria2 bundle in the set")
	}

	body, err := Render(hy2, entries, func(Entry) string { return "x" })
	if err != nil {
		t.Fatalf("an empty bundle failed to render: %v", err)
	}
	if !strings.Contains(body, "#profile-title:") {
		t.Fatalf("an empty bundle must still carry its header:\n%q", body)
	}
	// Header lines only: no node, and no bare scheme line either. The predecessor emitted a
	// naked "vmess://" in the neighbouring case, which a client reads as a broken entry.
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("an empty bundle emitted a body line: %q", line)
		}
	}

	// And the rest of the set is unaffected by that emptiness.
	for _, b := range Bundles() {
		if _, err := Render(b, entries, func(Entry) string { return "x" }); err != nil {
			t.Fatalf("%s failed to render: %v", b.Name, err)
		}
	}
}

func TestBundlesPartitionTheSet(t *testing.T) {
	entries := sample(t)
	label := func(e Entry) string { return e.Node.Short() }

	counts := map[string]int{}
	for _, b := range Bundles() {
		body, err := Render(b, entries, label)
		if err != nil {
			t.Fatalf("render %s: %v", b.Name, err)
		}
		counts[b.Name] = strings.Count(body, "://")
	}

	if counts["sub_all.txt"] != len(entries) {
		t.Fatalf("all bundle has %d nodes, want %d", counts["sub_all.txt"], len(entries))
	}
	// The whitelisted bundle is a subset of the whole, never larger than it, and there is no
	// second bundle carrying its complement: two files with identical contents whenever the
	// class is empty is what the complement actually shipped as (GHOST-029).
	if counts["sub_wl.txt"] > counts["sub_all.txt"] {
		t.Fatalf("wl (%d) cannot exceed all (%d)", counts["sub_wl.txt"], counts["sub_all.txt"])
	}
	for _, b := range Bundles() {
		if b.Name == "sub_open.txt" {
			t.Fatal("sub_open.txt is back: a bundle identical to sub_all.txt whenever the " +
				"whitelisted class is empty is two cards for one file")
		}
	}
	perProtocol := counts["sub_vless.txt"] + counts["sub_vmess.txt"] +
		counts["sub_trojan.txt"] + counts["sub_ss.txt"] + counts["sub_hy2.txt"]
	if perProtocol != counts["sub_all.txt"] {
		t.Fatalf("protocol bundles sum to %d, want %d", perProtocol, counts["sub_all.txt"])
	}
}

func TestHeaderIsPresentAndIntervalMatchesCadence(t *testing.T) {
	body, err := Render(Bundles()[0], sample(t), func(e Entry) string { return "n" })
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	lines := strings.Split(body, "\n")
	if !strings.HasPrefix(lines[0], "#profile-title:") {
		t.Fatalf("first line = %q", lines[0])
	}
	// The predecessor published six while running every four hours (GHOST-024).
	if lines[1] != "#profile-update-interval: 4" {
		t.Fatalf("second line = %q", lines[1])
	}
}

// Ordering is global and deterministic, and unmeasured latency sorts last rather than
// first. The predecessor sorted within each shard and concatenated the shards, producing
// sorted blocks the team believed were globally sorted.
func TestOrderingIsGlobalAndStable(t *testing.T) {
	entries := sample(t)
	label := func(e Entry) string { return e.Node.Short() }

	first, err := Render(Bundles()[0], entries, label)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	// Shuffling the input must not change the output.
	reversed := make([]Entry, len(entries))
	for i := range entries {
		reversed[i] = entries[len(entries)-1-i]
	}
	second, err := Render(Bundles()[0], reversed, label)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if first != second {
		t.Fatalf("input order changed the output:\n%s\n---\n%s", first, second)
	}

	// The fastest measured node comes first and the unmeasured one comes last.
	body := strings.Split(strings.TrimSpace(first), "\n")
	nodes := body[2:]
	if !strings.Contains(nodes[0], "b.example.com") {
		t.Fatalf("first node should be the 100ms one, got %s", nodes[0])
	}
	if !strings.HasPrefix(nodes[len(nodes)-1], "ss://") {
		t.Fatalf("the unmeasured node should sort last, got %s", nodes[len(nodes)-1])
	}
}
