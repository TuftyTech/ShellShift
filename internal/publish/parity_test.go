package publish

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tuftytech/shellshift/internal/decode"
)

// intentionalDrops are the only parameters publication is allowed to remove.
//
// The list is short and every entry has a reason. It exists as a test rather than a note
// because the analysis that produced it was a one-off measurement, and a one-off measurement
// decays: the next change that starts dropping something new would otherwise be invisible
// until a visitor client failed on a node we published.
var intentionalDrops = map[string]string{
	// The point of the project verification stance: a published URI never tells a client to
	// skip certificate verification (INV-38).
	"allowinsecure":  "never published: it disables certificate verification",
	"insecure":       "never published: it disables certificate verification",
	"allow_insecure": "never published: it disables certificate verification",

	// Vendor annotations. They name a channel or a client, not anything about the tunnel.
	"telegram": "vendor annotation, not a protocol parameter",
	"outline":  "vendor annotation, not a protocol parameter",

	// Aliases that survive under their canonical name.
	"servername": "an alias for sni, which is what gets published",
	"security":   "normalised: an implicit mode is published explicitly",

	// Fields with no meaning in the shape they were written on.
	"path": "carries no meaning on grpc, where the service name is authoritative",
	"fp":   "cleared on a node with no TLS, where a fingerprint means nothing",
}

func queryOf(uri string) map[string]string {
	out := map[string]string{}
	body, _, _ := strings.Cut(uri, "#")
	_, q, ok := strings.Cut(body, "?")
	if !ok {
		return out
	}
	for _, pair := range strings.Split(q, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		if k != "" {
			out[strings.ToLower(k)] = v
		}
	}
	return out
}

// INV-52. Publication may drop a parameter only for a stated reason, and the list of allowed
// losses is this test rather than a note: a one-off measurement goes stale, so the next change
// that starts losing something new fails in CI instead of being found by a visitor.
//
// Run against the sanitised structural corpus: one line per distinct parameter shape found in a
// real published catalogue of 865 nodes.
func TestOnlyIntentionalParametersAreDropped(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "tunnel", "testdata", "corpus.txt"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}

	unexpected := map[string]int{}
	examples := map[string]string{}
	checked := 0

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res, derr := decode.Decode(line)
		if derr != nil {
			continue
		}
		published, eerr := Encode(res.Node, "label")
		if eerr != nil {
			t.Errorf("encode: %v", eerr)
			continue
		}
		checked++

		before, after := queryOf(line), queryOf(published)
		for k, v := range before {
			if _, present := after[k]; present {
				continue
			}
			if _, allowed := intentionalDrops[k]; allowed {
				continue
			}
			unexpected[k]++
			if _, have := examples[k]; !have {
				examples[k] = k + "=" + v
			}
		}
	}

	if checked < 40 {
		t.Fatalf("only %d nodes checked: the corpus is not exercising the encoder", checked)
	}
	if len(unexpected) > 0 {
		keys := make([]string, 0, len(unexpected))
		for k := range unexpected {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Errorf("publication drops %q on %d nodes with no stated reason (example: %s)",
				k, unexpected[k], examples[k])
		}
		t.Log("either carry the parameter through model.PassThrough or add it to intentionalDrops with a reason")
	}
}

// No published value may differ from the source value for a parameter that is published at all.
// A silently rewritten value is worse than a dropped one: it looks intact.
func TestPublishedValuesAreNotSilentlyRewritten(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "tunnel", "testdata", "corpus.txt"))
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}

	// Keys whose value is normalised on purpose.
	normalised := map[string]bool{
		"type":     true, // transport aliases collapse to one name
		"sni":      true, // an address is not a valid server name and is dropped
		"mport":    true, // port ranges are canonicalised
		"plugin":   true, // the plugin name is canonicalised
		"security": true, // boolean-shaped values become mode names
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res, derr := decode.Decode(line)
		if derr != nil {
			continue
		}
		published, eerr := Encode(res.Node, "label")
		if eerr != nil {
			continue
		}
		before, after := queryOf(line), queryOf(published)
		for k, bv := range before {
			av, present := after[k]
			if !present || normalised[k] || av == bv {
				continue
			}
			t.Errorf("value of %q changed silently: %q -> %q", k, bv, av)
		}
	}
}
