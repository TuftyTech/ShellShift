package publish

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/model"
)

// The endpoint lives in the payload and nowhere in the page.
//
// GHOST-048 used to forbid host, port, credential and SNI in the dashboard outright, and this test
// enforced it. The rule is narrowed on the owner's decision, because a card that cannot show what a
// node is, and a list you cannot copy a node out of, are the two things the dashboard was asked
// for. What the rule protected against is still protected: the payload is a machine file beside the
// subscription that has published the same bytes since the first run, and the rendered HTML — the
// thing a crawler indexes and a screenshot leaks — carries none of it.
//
// So the assertion inverts rather than disappears: exactly once per node in the payload, nowhere at
// all in the page, neither as text nor inside an attribute.
func TestTheEndpointLivesInThePayloadAndNotInThePage(t *testing.T) {
	const (
		server = "secret-host.example.com"
		cred   = "b54f3d62-5a7c-4e8f-9b1a-2c3d4e5f6a7b"
		sni    = "front.example.org"
	)
	res, err := decode.Decode("vless://" + cred + "@" + server + ":8443?type=ws&security=tls&sni=" + sni + "&path=%2Fsecret")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	n := res.Node
	n.Country = "NL"
	n.Class = model.ClassOpen

	entries := []Entry{{
		Node: n,
		Verdict: model.Verdict{
			Identity: n.Key(), Proven: true, At: time.Now(),
			Measured: model.Measurement{Latency: 120 * time.Millisecond},
			Stages: []model.StageResult{
				{Stage: model.StagePolicy, Outcome: model.OutcomePass},
				{Stage: model.StageProof, Outcome: model.OutcomePass},
			},
		},
	}}

	data := BuildData(entries, Funnel{Collected: 10, Proven: 1},
		time.Now(), time.Minute, "sing-box/1.13.19", Extras{})

	var buf bytes.Buffer
	if err := WriteData(&buf, data); err != nil {
		t.Fatalf("write: %v", err)
	}
	payload := buf.String()
	for _, want := range []string{server, cred, sni, "8443", "/secret"} {
		if strings.Count(payload, want) == 0 {
			t.Errorf("the payload does not carry %q; the card has nothing to show", want)
		}
	}
	if !strings.Contains(payload, n.Short()) {
		t.Error("the payload must still carry the short display identifier")
	}
	if !strings.Contains(payload, `"cc":"NL"`) {
		t.Error("the payload must still carry the country")
	}

	// And the page carries none of it. Attributes count: `data-host="..."` would be invisible on
	// screen and perfectly indexable, which is the failure this half of the rule is about.
	page := render(t, data, "ru", data.GeneratedAt)
	for _, forbidden := range []string{cred, server, sni, "/secret"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the rendered page leaks %q", forbidden)
		}
	}
}

func TestUnmeasuredValuesAreAbsentNotZero(t *testing.T) {
	res, err := decode.Decode("ss://aes-256-gcm:pw@example.com:8388")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	entries := []Entry{{Node: res.Node, Verdict: model.Verdict{Proven: true, At: time.Now()}}}

	var buf bytes.Buffer
	if err := WriteData(&buf, BuildData(entries, Funnel{}, time.Now(), 0, "e", Extras{})); err != nil {
		t.Fatalf("write: %v", err)
	}
	body := buf.String()
	for _, absent := range []string{`"latency_ms":0`, `"mbps":0`} {
		if strings.Contains(body, absent) {
			t.Fatalf("payload publishes %s instead of omitting it:\n%s", absent, body)
		}
	}
}

// PERF-041 again, on the data file this time.
func TestDataPayloadIsByteStable(t *testing.T) {
	var entries []Entry
	for _, host := range []string{"c.example.com", "a.example.com", "b.example.com"} {
		res, err := decode.Decode("trojan://pw@" + host + ":443?security=tls")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		entries = append(entries, Entry{Node: res.Node, Verdict: model.Verdict{Proven: true}})
	}
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	var first, second bytes.Buffer
	if err := WriteData(&first, BuildData(entries, Funnel{}, at, time.Minute, "e", Extras{})); err != nil {
		t.Fatalf("write: %v", err)
	}
	reversed := []Entry{entries[2], entries[0], entries[1]}
	if err := WriteData(&second, BuildData(reversed, Funnel{}, at, time.Minute, "e", Extras{})); err != nil {
		t.Fatalf("write: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("input order changed the payload bytes")
	}
}

// The funnel is the honest rendering of the pipeline, and the payload must carry it: the
// predecessor emitted no such breakdown, which is why its dashboard could only assert that
// verification had happened.
func TestFunnelIsPublished(t *testing.T) {
	data := BuildData(nil, Funnel{Collected: 65000, Decoded: 41000, Policy: 40800, Reached: 8300, Proven: 865},
		time.Now(), time.Minute, "sing-box/1.13.19",
		Extras{Rejections: map[string]int{"bad_host": 12}})

	var buf bytes.Buffer
	if err := WriteData(&buf, data); err != nil {
		t.Fatalf("write: %v", err)
	}
	body := buf.String()
	for _, want := range []string{`"collected":65000`, `"proven":865`, `"bad_host":12`, "sing-box/1.13.19"} {
		if !strings.Contains(body, want) {
			t.Fatalf("payload missing %s:\n%s", want, body)
		}
	}
}
