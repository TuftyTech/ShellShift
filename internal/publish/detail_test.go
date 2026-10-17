package publish

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/policy"
)

// richEntry is one node carrying every parameter the decoder accepts, verified, located and
// classified — the input the card was designed for.
func richEntry(t *testing.T) (Entry, Extras) {
	t.Helper()
	res, err := decode.Decode("vless://" + uuid + "@node.example.com:8443" +
		"?type=ws&security=reality&sni=www.microsoft.com&pbk=" + pbk +
		"&sid=6ba85179e3&fp=chrome&alpn=h2%2Chttp%2F1.1&flow=xtls-rprx-vision" +
		"&path=%2Fws&host=cdn.example.net&packetEncoding=xudp#node")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	n := res.Node
	n.Source = "https://feeds.example.org/list/subscribe.txt?token=secret"
	n.Country, n.CountryName, n.City = "DE", "Germany", "Nuremberg"
	n.Addr, n.Timezone = "88.99.1.1", "Europe/Berlin"
	n.ASN, n.ASName = "AS24940 Hetzner Online GmbH", "HETZNER-AS"
	n.ISP, n.Org = "Hetzner Online GmbH", "Hetzner Online GmbH"
	n.Reverse = "static.88-99-1-1.clients.your-server.de"
	n.Class = model.ClassWhitelisted
	n.ClassReason = string(policy.ReasonWhitelisted)

	e := Entry{
		Node: n,
		Verdict: model.Verdict{
			Identity: n.Key(), Proven: true,
			At:       time.Date(2026, 9, 3, 22, 55, 17, 0, time.UTC),
			Measured: model.Measurement{Latency: 137 * time.Millisecond, Mbps: 18.4, Bytes: 262144},
			Stages: []model.StageResult{
				{Stage: model.StagePolicy, Outcome: model.OutcomePass, Elapsed: 2 * time.Millisecond},
				{Stage: model.StageReach, Outcome: model.OutcomeSkipped},
				{Stage: model.StageProof, Outcome: model.OutcomePass, Elapsed: 137 * time.Millisecond},
				{Stage: model.StageThroughput, Outcome: model.OutcomeFail, Reason: "sample too short"},
			},
		},
	}
	x := Extras{
		History: map[string]NodeHistory{n.Key(): {
			Proofs: 42, Failures: 3,
			FirstSeen: time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC),
		}},
		Covers: map[string]policy.CoverCert{"www.microsoft.com": {
			Issuer:     "Microsoft Azure RSA TLS Issuing CA 03",
			Subject:    "www.microsoft.com",
			NotBefore:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:   time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
			TLSVersion: "TLS 1.3",
			Proven:     true,
		}},
	}
	return e, x
}

// Everything the run learned about a node reaches the card.
//
// The payload used to be a projection of five fields, so the page could say that verification
// happened and nothing about what was verified. A reader looking at a node they are already using
// could not even confirm it was the same node. Every field asserted here was measured or fetched
// during the run and then discarded at publication — the card costs no new request to anybody.
func TestEveryKnownFactReachesTheDetail(t *testing.T) {
	e, x := richEntry(t)
	data := BuildData([]Entry{e}, Funnel{Collected: 1, Proven: 1},
		time.Now(), time.Minute, "sing-box/1.13.19", x)

	if len(data.Nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(data.Nodes))
	}
	d := data.Nodes[0].Detail
	if d == nil {
		t.Fatal("the node carries no detail at all")
	}

	for _, tc := range []struct{ name, got, want string }{
		{"server", d.Server, "node.example.com"},
		{"credential", d.Credential, uuid},
		{"security", d.Security, "reality"},
		{"sni", d.SNI, "www.microsoft.com"},
		{"host", d.Host, "cdn.example.net"},
		{"path", d.Path, "/ws"},
		{"public key", d.PublicKey, pbk},
		{"short id", d.ShortID, "6ba85179e3"},
		{"fingerprint", d.Fingerprint, "chrome"},
		{"packet encoding", d.Encoding, "xudp"},
		{"country", d.CountryName, "Germany"},
		{"city", d.City, "Nuremberg"},
		{"address", d.Addr, "88.99.1.1"},
		{"timezone", d.Timezone, "Europe/Berlin"},
		{"asn", d.ASN, "AS24940 Hetzner Online GmbH"},
		{"as name", d.ASName, "HETZNER-AS"},
		{"isp", d.ISP, "Hetzner Online GmbH"},
		{"network owner", d.Org, "Hetzner Online GmbH"},
		{"reverse name", d.Reverse, "static.88-99-1-1.clients.your-server.de"},
		{"class reason", d.ClassReason, string(policy.ReasonWhitelisted)},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if d.Port != 8443 {
		t.Errorf("port = %d, want 8443", d.Port)
	}
	if strings.Join(d.ALPN, ",") != "h2,http/1.1" {
		t.Errorf("alpn = %v, want h2,http/1.1", d.ALPN)
	}
	// Flow is absent here on purpose, and that absence is a rule rather than an omission: the
	// decoder drops xtls-rprx-vision unless the transport is raw TCP (INV-01), because a client
	// handed flow over a WebSocket builds a different connection than the one that was proven. So
	// the card must show what will be dialled, not what the source wrote.
	if d.Flow != "" {
		t.Errorf("flow = %q over a WebSocket transport; INV-01 says the decoder drops it", d.Flow)
	}
	tcpRes, err := decode.Decode("vless://" + uuid + "@tcp.example.com:443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&pbk=" + pbk +
		"&sid=6ba85179e3&fp=chrome&flow=xtls-rprx-vision")
	if err != nil {
		t.Fatalf("decode tcp: %v", err)
	}
	tcpData := BuildData([]Entry{{Node: tcpRes.Node, Verdict: model.Verdict{Proven: true}}},
		Funnel{Collected: 1, Proven: 1}, time.Now(), time.Minute, "e", Extras{})
	if got := tcpData.Nodes[0].Detail.Flow; got != "xtls-rprx-vision" {
		t.Errorf("flow over raw TCP = %q, want xtls-rprx-vision", got)
	}

	if d.Bytes != 262144 {
		t.Errorf("bytes = %d, want 262144", d.Bytes)
	}
	if d.Proofs != 42 || d.Failures != 3 {
		t.Errorf("history = %d proofs, %d failures; want 42 and 3", d.Proofs, d.Failures)
	}
	if d.FirstSeen == nil || !d.FirstSeen.Equal(time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("first seen = %v, want 2026-08-01T06:00:00Z", d.FirstSeen)
	}

	// The feed is named by host and not by URL. A subscription URL in a public file is a line
	// somebody copies, and the token on the end of this one is why.
	if d.Source != "feeds.example.org" {
		t.Errorf("source = %q, want the feed's host alone", d.Source)
	}

	// Every stage, with its outcome, its reason and its time — the whole verification record,
	// because "proven" without the stages is the assertion this project refuses to make.
	if len(d.Stages) != 4 {
		t.Fatalf("stages = %d, want 4: %+v", len(d.Stages), d.Stages)
	}
	if d.Stages[0].Stage != "policy" || d.Stages[0].Outcome != "pass" || d.Stages[0].MS != 2 {
		t.Errorf("first stage = %+v", d.Stages[0])
	}
	if d.Stages[3].Reason != "sample too short" {
		t.Errorf("a failed stage lost its reason: %+v", d.Stages[3])
	}

	// The certificate behind the class, keyed by the name the classifier probed.
	if d.Cover == nil {
		t.Fatal("a whitelisted node carries no cover certificate")
	}
	if d.Cover.Issuer != "Microsoft Azure RSA TLS Issuing CA 03" || d.Cover.Subject != "www.microsoft.com" {
		t.Errorf("cover = %+v", d.Cover)
	}
	if d.Cover.TLS != "TLS 1.3" || !d.Cover.Proven {
		t.Errorf("cover verdict = %+v", d.Cover)
	}
	if d.Cover.From == nil || d.Cover.To == nil {
		t.Errorf("cover validity missing: %+v", d.Cover)
	}
}

// The URI on the card is the line the subscription publishes, not a second rendering of it.
//
// Two renderings of the same node is exactly the shape of defect this project's fidelity gates
// exist for: a reader copying from the card and a client reading the subscription must dial the
// same thing, and the label carries the display code, which is assigned across the whole set.
func TestTheCardsURIIsTheSubscriptionLine(t *testing.T) {
	e, x := richEntry(t)
	second, _ := richEntry(t)
	second.Node.Identity.Server = "other.example.com"
	second.Verdict.Measured.Latency = 90 * time.Millisecond
	entries := []Entry{e, second}

	data := BuildData(entries, Funnel{Collected: 2, Proven: 2},
		time.Now(), time.Minute, "e", x)

	codes := ShortCodes(entries)
	body, err := Render(Bundles()[0], entries, func(en Entry) string {
		return Label(en.Node, codes[en.Node.Key()])
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "vless://") {
			lines[l] = true
		}
	}
	if len(lines) != 2 {
		t.Fatalf("the bundle rendered %d lines, want 2", len(lines))
	}
	for _, row := range data.Nodes {
		if row.Detail == nil {
			t.Fatalf("node %s has no detail", row.ID)
		}
		if !lines[row.Detail.URI] {
			t.Errorf("the card's URI for %s is not a line in sub_all.txt:\n  card: %s",
				row.ID, row.Detail.URI)
		}
	}
}

// An unmeasured node publishes no measurements, and a node with no proof to make publishes no
// certificate. This is INV-36 applied to the card: the predecessor's habit was to fill a gap with a
// zero and then filter the zero out again downstream.
func TestTheDetailOmitsWhatWasNotMeasured(t *testing.T) {
	res, err := decode.Decode("trojan://hunter2@bare.example.com:443?security=tls")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	e := Entry{Node: res.Node, Verdict: model.Verdict{
		Identity: res.Node.Key(), Proven: true, At: time.Now(),
	}}

	data := BuildData([]Entry{e}, Funnel{Collected: 1, Proven: 1},
		time.Now(), time.Minute, "e", Extras{})
	d := data.Nodes[0].Detail
	if d == nil {
		t.Fatal("no detail")
	}
	if d.Bytes != 0 || d.Proofs != 0 || d.Failures != 0 {
		t.Errorf("unmeasured figures were invented: %+v", d)
	}
	if d.FirstSeen != nil {
		t.Errorf("first seen = %v, want absent: the ledger said nothing about this node", d.FirstSeen)
	}
	if d.Cover != nil {
		t.Errorf("cover = %+v, want absent: no masking proof was made", d.Cover)
	}
	if len(d.Stages) != 0 {
		t.Errorf("stages = %+v, want none", d.Stages)
	}
	// And nothing about the empty fields reaches the file as a zero.
	var sb strings.Builder
	if err := WriteData(&sb, data); err != nil {
		t.Fatalf("write: %v", err)
	}
	// SNI is deliberately not in this list: the decoder normalises a TLS node with no explicit
	// sni to its host, so this node really does have one. The list is about measurements that were
	// never taken, not about configuration the source left implicit.
	for _, forbidden := range []string{`"bytes":0`, `"proofs":0`, `"first_seen"`, `"cover"`, `"mbps"`} {
		if strings.Contains(sb.String(), forbidden) {
			t.Errorf("the payload carries %s for a node that has none", forbidden)
		}
	}
}

// --- the card on the page ---------------------------------------------------------------

// The card's labels ship in the markup, in both languages, and every field the payload can carry
// has one.
//
// The card is assembled by the script, so its labels cannot come from the payload: a value with no
// label is a number nobody can read, and a label baked into site.js would be the one string on this
// page that cannot be translated and cannot be checked from Go. They ride in a <template>, which is
// also why detailSections() lives in Go rather than in the stylesheet or the script.
func TestTheCardsLabelsShipInBothLanguages(t *testing.T) {
	e, x := richEntry(t)
	data := BuildData([]Entry{e}, Funnel{Collected: 1, Proven: 1}, time.Now(), time.Minute, "e", x)
	html := render(t, data, "ru", data.GeneratedAt)

	if !strings.Contains(html, `data-testid="node-detail-tpl"`) {
		t.Fatal("the card template does not render")
	}
	if !strings.Contains(html, `data-testid="node-detail"`) {
		t.Fatal("the dialog does not render")
	}

	fields := 0
	for _, sec := range detailSections() {
		for _, lang := range Languages {
			if translations[lang][sec.Key] == "" {
				t.Errorf("section heading %q is missing from the %s table", sec.Key, lang)
			}
		}
		if !onPage(html, translations["ru"][sec.Key]) {
			t.Errorf("section %q does not render", sec.Key)
		}
		for _, f := range sec.Fields {
			fields++
			key := "detail_" + f
			for _, lang := range Languages {
				if translations[lang][key] == "" {
					t.Errorf("label %q is missing from the %s table", key, lang)
				}
			}
			if !strings.Contains(html, `data-field="`+f+`"`) {
				t.Errorf("field %q has no row in the template", f)
			}
		}
	}
	if fields < 30 {
		t.Errorf("the card describes %d fields; the payload carries far more than that", fields)
	}

	// Every field the payload can hold appears in some section. A field added to NodeDetail and
	// forgotten here is data the run collected and the page silently drops — which is the whole
	// defect this feature exists to close, reintroduced one field at a time.
	described := map[string]bool{}
	for _, sec := range detailSections() {
		for _, f := range sec.Fields {
			described[f] = true
		}
	}
	// The payload's own names, from the JSON tags, minus the ones the card renders as part of
	// another row: the four cover fields are shown as cover_*, and place merges country and city.
	rendered := map[string]bool{
		"cover": true, "country": true, "city": true, "uri": true,
	}
	for _, name := range payloadFieldNames(t) {
		if !described[name] && !rendered[name] {
			t.Errorf("the payload carries %q and no section shows it", name)
		}
	}
}

// payloadFieldNames lists the json names of NodeDetail's fields.
func payloadFieldNames(t *testing.T) []string {
	t.Helper()
	rt := reflect.TypeOf(NodeDetail{})
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	return out
}

// The row points at its node by position, and a payload without detail offers nothing.
//
// Position rather than the eight-hex display id: over a corpus of this size two ids can collide,
// and the card would then describe a different node than the row it was opened from — a mistake
// that would be invisible and total. A payload written before the card existed produces rows with
// no position at all, so the script adds no controls rather than opening empty cards.
func TestTheRowPointsAtItsNodeByPosition(t *testing.T) {
	e, x := richEntry(t)
	second, _ := richEntry(t)
	second.Node.Identity.Server = "other.example.com"
	data := BuildData([]Entry{e, second}, Funnel{Collected: 2, Proven: 2},
		time.Now(), time.Minute, "e", x)

	html := render(t, data, "ru", data.GeneratedAt)
	for i := range data.Nodes {
		if !strings.Contains(html, `data-node="`+strconv.Itoa(i)+`"`) {
			t.Errorf("no row points at payload position %d", i)
		}
	}
	if got := strings.Count(html, "data-node="); got != len(data.Nodes) {
		t.Errorf("%d rows point at a node, want %d", got, len(data.Nodes))
	}

	// A payload from before version 2: same rows, no detail, so no affordance.
	stale := data
	stale.Nodes = make([]NodeRow, len(data.Nodes))
	copy(stale.Nodes, data.Nodes)
	for i := range stale.Nodes {
		stale.Nodes[i].Detail = nil
	}
	old := render(t, stale, "ru", data.GeneratedAt)
	if strings.Contains(old, "data-node=") {
		t.Error("a payload with no detail must not offer a card")
	}
	if !strings.Contains(old, `data-testid="node-rows"`) {
		t.Error("the table itself must still render")
	}
}

// An empty field is hidden, and the stylesheet has to let it be.
//
// fill() hides a row whose value is empty by setting the hidden attribute, but .nd-row sets
// display: grid, and an author display rule outranks the UA's [hidden] { display: none }. The
// card shipped like that: every absent field still printed its label, which reads as a
// measurement of nothing — exactly what hiding it was for.
func TestEmptyCardRowsAreActuallyHidden(t *testing.T) {
	css := readAsset(t, "assets/site.css")
	for _, want := range []string{".nd-row[hidden]", ".nd-sec[hidden]"} {
		if !strings.Contains(css, want) {
			t.Errorf("site.css has no %s rule: a hidden card row still renders, because .nd-row sets display", want)
		}
	}
}

// The credential is masked until a reader asks for it, and the page never carries it.
//
// This is the narrowed GHOST-048 in its enforceable form. The endpoint is in the payload because
// the card and the copy button cannot exist without it; what must stay true is that the rendered
// page carries none of it, and that the interface does not put a stranger's password on screen
// merely because somebody opened a card.
func TestTheSecretIsMaskedUntilAsked(t *testing.T) {
	js := readAsset(t, "assets/site.js")

	for _, want := range []string{
		"function mask(",                 // there is a masking function at all
		`case "credential":`,             // and the credential goes through it
		`case "server":`,                 // as does the server address
		`case "addr":`,                   // and the address it resolved to, which is the same secret
		`case "ptr":`,                    // and the reverse name, which usually spells the address out
		`data-secret`,                    // the reveal state lives on the dialog
		`removeAttribute("data-secret")`, // and it is dropped when the card closes
	} {
		if !strings.Contains(js, want) {
			t.Errorf("site.js does not contain %q: the mask is not implemented as described", want)
		}
	}

	// The link is masked whole, not by searching it for the credential. A search misses the server
	// in the authority, and it misses Shadowsocks and VMess entirely, whose secret travels base64-
	// encoded: the card printed the full link for those while saying the credential was hidden.
	if strings.Contains(js, "d.uri.replace(") {
		t.Error("the masked link is derived by searching the URI for the credential, which leaks base64-encoded secrets")
	}
	if !strings.Contains(js, `if (shown) return d.uri;`) {
		t.Error("the full link must be returned only when the reader asked for it")
	}

	// The reveal must be a deliberate act, so the card cannot open with the secret shown: the
	// masked branch is the default and `shown` is what the attribute has to prove.
	if !strings.Contains(js, `dialog.getAttribute("data-secret") === "shown"`) {
		t.Error("the card must default to masked and require the attribute to reveal")
	}

	// And the labels for both states exist, or the button can only be honest in one language.
	for _, key := range []string{"detail_reveal", "detail_hide", "detail_secret_note"} {
		for _, lang := range Languages {
			if translations[lang][key] == "" {
				t.Errorf("%q is missing from the %s table", key, lang)
			}
		}
	}
}
