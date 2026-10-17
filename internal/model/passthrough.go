package model

import "strings"

// PassThrough is the set of query parameters that are carried from a source URI to the
// published one without the engine acting on them.
//
// This is deliberately an allowlist and not a bag. The predecessor kept an unbounded raw_meta
// map on every node, re-serialised it into the engine payload and again into the published URI,
// and that map was both a memory cost on every node and an unvalidated path from a hostile
// source into a generated configuration.
//
// But dropping everything unmodelled is also wrong, and measurement says so: comparing 100
// distinct parameter shapes from a real published catalogue against their republished forms
// showed twelve carrying a Reality spiderX value that sing-box ignores and Xray-based clients
// use. A node that survives publication and stops working in the visitor client is a node we
// broke.
//
// So: a named set, each with a bound on what it may contain, carried through and re-emitted.
var PassThrough = map[string]PassThroughRule{
	// Reality spiderX. sing-box does not implement it; Xray does.
	"spx": {MaxLen: 256},
	// gRPC authority override, used by some clients in place of the Host header.
	"authority": {MaxLen: 253},
	// Multiplexing hints. sing-box configures multiplexing structurally rather than through
	// the URI, so these reach the visitor client and not our engine.
	"mux":            {MaxLen: 16},
	"muxconcurrency": {MaxLen: 8},
	// TLS extensions some clients support and sing-box exposes differently. The bounds here
	// come from measurement rather than instinct: a real ECH configuration list in the corpus
	// is 2.3 KB and a post-quantum verify value is 2.7 KB, so a bound chosen by feel drops
	// exactly the parameters it was meant to carry.
	"fragment": {MaxLen: 128},
	"ech":      {MaxLen: 4096},
	"pqv":      {MaxLen: 4096},
	"fm":       {MaxLen: 64},
	"prefix":   {MaxLen: 128},
	// Transport mode for the split-http family.
	"mode": {MaxLen: 32},
}

// PassThroughRule bounds one carried parameter.
type PassThroughRule struct {
	// MaxLen caps the value length. A carried value still crosses a trust boundary, so it is
	// bounded even though nothing here interprets it.
	MaxLen int
}

// MaxCarriedBytes caps the total carried payload for one node.
//
// The per-parameter bounds allow kilobytes because real values are kilobytes. A total bound is
// what stops a hostile source from attaching the maximum of every carried key to every node it
// publishes and inflating the whole catalogue.
const MaxCarriedBytes = 8192

// TrimCarried enforces the total bound, dropping the largest values first so the small,
// numerous parameters survive.
func TrimCarried(carried map[string]string) map[string]string {
	total := 0
	for k, v := range carried {
		total += len(k) + len(v)
	}
	if total <= MaxCarriedBytes {
		return carried
	}
	// Drop the largest until the rest fits. A partially carried set is still faithful about
	// what it does carry, and the alternative is dropping everything.
	type entry struct {
		key  string
		size int
	}
	entries := make([]entry, 0, len(carried))
	for k, v := range carried {
		entries = append(entries, entry{k, len(k) + len(v)})
	}
	for len(entries) > 0 && total > MaxCarriedBytes {
		largest := 0
		for i := range entries {
			if entries[i].size > entries[largest].size {
				largest = i
			}
		}
		delete(carried, entries[largest].key)
		total -= entries[largest].size
		entries = append(entries[:largest], entries[largest+1:]...)
	}
	return carried
}

// CarryParam reports whether a parameter should be carried, and its cleaned value.
//
// A value that fails the bound is dropped rather than truncated: half a parameter is not a
// smaller version of that parameter, it is a different one.
func CarryParam(key, value string) (string, bool) {
	rule, ok := PassThrough[strings.ToLower(strings.TrimSpace(key))]
	if !ok {
		return "", false
	}
	v := strings.TrimSpace(value)
	if v == "" || len(v) > rule.MaxLen {
		return "", false
	}
	// Control characters cannot appear in a URI query value, and a carried value is written
	// straight back out, so this is the one thing worth checking about content.
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return v, true
}
