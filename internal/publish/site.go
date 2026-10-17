package publish

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/tuftytech/shellshift/internal/policy"
)

// assets holds the site sources, compiled into the binary.
//
// They live beside the renderer rather than at the repository root because go:embed cannot
// reach outside its own package directory — and having the template next to the code that
// fills it is no loss.
//
// Embedding means the published site cannot drift from the binary that produced it, and
// there is no build step that has to be remembered. The predecessor assembled its page with
// twenty-two chained string replacements against a template read from disk at run time, and
// a token with no matching replacement was rewritten to a dash by a safety net that existed
// because a visible one had already shipped (INV-44).
//
//go:embed all:site
var assets embed.FS

// SiteData is what the template is given.
type SiteData struct {
	Data
	// Origin is the published site origin, used to build subscription links.
	Origin string
	// AssetBase prefixes every asset and sibling link so a page one directory down still
	// finds the stylesheet. Getting this wrong is how a translated page ships unstyled.
	AssetBase string
	// SourcesURL is the repository link, or empty to render no link at all rather than a
	// control that goes nowhere.
	SourcesURL string
	// Bundles pairs each published file with its node count.
	Bundles []BundleSummary
	// Rows is the node table — a second projection, narrower than NodeRow, holding only
	// what a cell prints. Formatting here rather than in the template keeps the display
	// rules in one language instead of two.
	Rows []TableRow
	// Filters lists the protocols that actually have proven nodes, so the chip row never
	// offers a filter that can only ever return nothing.
	Filters []string
	// Freshness is the band the heartbeat renders: live, aging, stale or unknown.
	Freshness string
	// AgeHours is how old the data is, for the readout.
	AgeHours float64
	// Mix is the catalogue-composition band: one bar column per distribution.
	//
	// Protocols and countries are two views of the same corpus and are drawn by the same
	// mark, so they are one slice of bands rather than two fields with two copies of the
	// bar markup. The hero used to carry "14 countries" and "5 protocols" as tiles; both
	// numbers are the length of a band here, which is the one place they are also legible.
	Mix []MixBand
	// ClassNote names the string that explains an empty whitelisted class, or is empty when
	// the class has members and needs no explanation.
	//
	// Without it the card read "whitelisted — 0 nodes" and stopped there, which is the same
	// number whether no node qualified or the whitelist feed never loaded and the check
	// never ran. The run report could always tell those apart and the page could not.
	ClassNote string
	// HasMasked and HasMbps say whether the two conditional markers in the node table are
	// present in this corpus, so the legend under it can describe the table it sits under.
	// It promised a WL marker and a second latency line unconditionally, and in a run with
	// no whitelisted node and no throughput measurement neither appears anywhere — a legend
	// for markup that is not on the page.
	HasMasked bool
	HasMbps   bool
	// BuildTime stamps the page so a test can pin relative-time rendering.
	BuildTime time.Time
}

// BundleSummary describes one published subscription file.
type BundleSummary struct {
	Name  string
	Title string
	Count int
	// Note names the string that says what this file contains, or is empty for the
	// per-protocol files whose title already says it. The two class files needed it: "all"
	// and "whitelisted" are not self-explanatory, and a reader looking at two cards with
	// different counts and no statement of the difference has to guess at the one decision
	// the project is actually making.
	Note string
}

// MixBand is one distribution column: a heading, and the rows it plots.
//
// Max is carried rather than read off the first row so the template does not have to know
// that the rows are sorted, and so an empty band cannot index out of range.
type MixBand struct {
	// Key names the band's heading in the string table.
	Key string
	// TestID is the band's hook for a test and for the dashboard's own diagnostics.
	TestID string
	Rows   []MixRow
	Max    int
	// Total is how many distinct labels the corpus has, before the cap. The heading shows
	// it rather than len(Rows): the band plots the largest eight, and a heading that
	// counted its own bars would report eight countries in a corpus that has fourteen.
	Total int
}

// MixRow is one bar: the label, and how many proven nodes carry it.
type MixRow struct {
	Label string
	Count int
}

// TableRow is one row of the node table.
//
// Latency, Mbps and Verified are strings because an absent measurement must render as
// nothing at all, and a numeric zero in a struct cannot express that (INV-36). Masked is
// the wl class: the node's Reality masking was checked against the real site at its SNI,
// which is the one piece of per-node state that varies and is therefore worth a column.
type TableRow struct {
	Protocol  string
	CC        string
	Transport string
	ID        string
	Latency   string
	Mbps      string
	Streak    string
	Verified  string
	Masked    bool
	// Node is the row's index in the payload's own node array, or empty when that payload
	// carries no detail for it.
	//
	// An index and not the display id: the id is eight hex characters of a hash, and over a
	// corpus this size a collision is unlikely rather than impossible — the card would then show
	// the wrong node's configuration, which is the one mistake this feature must not make. The
	// index is exact, costs sixteen bytes a row, and the payload's order is byte-stable.
	Node string
}

// Freshness bands are driven by the real cadence rather than a hardcoded badge. The
// predecessor rendered "active" with a pulsing dot, unconditionally and with no data
// binding, so a pipeline that had been dead for two days still claimed to be running.
const (
	FreshnessLive    = "live"
	FreshnessAging   = "aging"
	FreshnessStale   = "stale"
	FreshnessUnknown = "unknown"
)

// freshnessFor bands an age against a roughly four-hourly cadence.
func freshnessFor(age time.Duration, known bool) string {
	switch {
	case !known:
		return FreshnessUnknown
	case age < FreshnessLiveUntil:
		return FreshnessLive
	case age < FreshnessAgingUntil:
		return FreshnessAging
	default:
		return FreshnessStale
	}
}

// The two band edges, exported because the page carries them as data attributes and the script
// re-bands the strip from them as the page ages in a tab or on a host that serves a cached copy.
// A second copy of "five hours" inside site.js would be a threshold that could drift from this
// one with nothing to notice; rendering them means there is one number and the client reads it.
const (
	FreshnessLiveUntil  = 5 * time.Hour
	FreshnessAgingUntil = 9 * time.Hour
)

// BuildSiteData assembles what the page needs from a published payload.
func BuildSiteData(d Data, origin string, now time.Time) SiteData {
	byCC := map[string]int{}
	byProtocol := map[string]int{}
	byBundle := map[string]int{}
	var hasMasked, hasMbps bool
	for _, row := range d.Nodes {
		if row.CC != "" {
			byCC[row.CC]++
		}
		byProtocol[row.Protocol]++
		byBundle["sub_all.txt"]++
		if row.Class == "wl" {
			byBundle["sub_wl.txt"]++
			hasMasked = true
		}
		if row.Mbps > 0 {
			hasMbps = true
		}
		byBundle["sub_"+shortProtocol(row.Protocol)+".txt"]++
	}

	summaries := make([]BundleSummary, 0, len(Bundles()))
	for _, b := range Bundles() {
		summaries = append(summaries, BundleSummary{
			Name: b.Name, Title: b.Title, Count: byBundle[b.Name], Note: bundleNotes[b.Name],
		})
	}

	// Protocols first: it is the shorter band, and it is the one the table below is filtered
	// by, so the band reads as the legend for the filter chips rather than as a second chart.
	mix := make([]MixBand, 0, 2)
	if band := mixBand("protocols", "protocol-bars", byProtocol, 8); len(band.Rows) > 0 {
		mix = append(mix, band)
	}
	if band := mixBand("countries", "country-bars", byCC, 8); len(band.Rows) > 0 {
		mix = append(mix, band)
	}

	filters := make([]string, 0, len(byProtocol))
	for p := range byProtocol {
		filters = append(filters, p)
	}
	sort.Strings(filters)

	known := !d.GeneratedAt.IsZero()
	age := now.Sub(d.GeneratedAt)

	return SiteData{
		Data:       d,
		Origin:     origin,
		SourcesURL: SourcesURL,
		Bundles:    summaries,
		Rows:       buildRows(d.Nodes),
		Filters:    filters,
		Freshness:  freshnessFor(age, known),
		AgeHours:   age.Hours(),
		Mix:        mix,
		ClassNote:  classNote(byBundle["sub_wl.txt"], d.ClassReasons),
		HasMasked:  hasMasked,
		HasMbps:    hasMbps,
		BuildTime:  now,
	}
}

// DetailSection is one block of the node card: a heading and the fields under it, in reading
// order.
//
// The list lives in Go rather than in the template for two reasons. The card is built by the
// script from the payload, so its labels have to reach the page some other way — they ship inside
// a <template> rendered from this list, in both languages, like every other string here. And a
// field added to the payload without a label would otherwise render as a value with nothing to
// say what it is; walking this list, TestStringsNamedFromGoExistInBothLanguages fails instead.
type DetailSection struct {
	// Key is the heading's string key. Fields are field names; each one's label is
	// "detail_" + name, and the script fills the value by matching data-field.
	Key    string
	Fields []string
}

// detailSections is the card's shape: what a reader is told about a node, and in what order.
//
// Connection first, because "is this the node I am using" is the question that brings somebody
// here, and it is answered by the address and the credential. Then whose machine it is, then what
// was actually proven, then the class and the disguise behind it. The source feed is last: it
// matters least to a reader and most to us.
func detailSections() []DetailSection {
	return []DetailSection{
		{"detail_sec_conn", []string{
			"uri", "server", "port", "port_range", "security", "sni", "host", "path",
			"pbk", "sid", "fp", "alpn", "flow", "packet_encoding", "aid", "obfs", "method",
			"plugin", "credential",
		}},
		{"detail_sec_net", []string{
			"addr", "ptr", "asn", "asname", "isp", "org", "place", "tz",
		}},
		{"detail_sec_proof", []string{
			"latency", "mbps", "bytes", "streak", "proofs", "failures", "first_seen", "stages",
		}},
		{"detail_sec_class", []string{
			"class", "class_reason", "cover_subject", "cover_issuer", "cover_valid", "cover_tls",
			"source",
		}},
	}
}

// legalItems are the notice's statements, in the order the page renders them.
//
// Each name is a string key, and its body is the same key with "_body". The list is data rather
// than markup so that a test can walk it — the template builds the body keys with printf, which
// the template scanner in TestEveryTemplateKeyExistsInBothLanguages cannot see, so
// TestStringsNamedFromGoExistInBothLanguages walks this slice instead. A statement added in
// Russian and forgotten in English is the failure a bilingual legal notice cannot have: a missing
// key aborts the render of the whole page, so a run that verified a catalogue publishes nothing.
//
// The order is not arbitrary. What the project is comes before what it is not liable for,
// because a reader who stops after two items should have read the two that matter: it runs no
// servers, and the data was already public.
var legalItems = []string{
	"legal_role",
	"legal_source",
	"legal_relation",
	"legal_no_data",
	"legal_no_warranty",
	"legal_user",
	"legal_operator",
	"legal_takedown",
	"legal_marks",
}

// bundleNotes names the string that describes each file, one per bundle.
//
// It began as two entries, for the two class files whose titles say nothing on their own, and that
// was the defect: a row of cards where one carried three lines and its neighbour carried none read
// as broken, and "ShellShift — vless" is only self-explanatory to a reader who already knows what
// VLESS is — which is not the reader a subscription file exists for. Every bundle now says what it
// holds and when to prefer it, and TestEveryCardSaysWhatItHolds fails if a new bundle arrives
// without a sentence.
var bundleNotes = map[string]string{
	"sub_all.txt":    "bundle_note_all",
	"sub_wl.txt":     "bundle_note_wl",
	"sub_vless.txt":  "bundle_note_vless",
	"sub_vmess.txt":  "bundle_note_vmess",
	"sub_trojan.txt": "bundle_note_trojan",
	"sub_ss.txt":     "bundle_note_ss",
	"sub_hy2.txt":    "bundle_note_hy2",
}

// classNote turns the classification histogram into the one sentence the whitelisted card
// needs when it is empty, and returns "" when it is not.
//
// The mapping is on policy.Reason rather than on literal strings so that renaming a reason is
// a compile error here instead of a card that silently falls back to the vaguest wording. An
// unrecognised reason still produces a note — the generic one — because a class with no
// members and no explanation is the state this function exists to remove.
func classNote(whitelisted int, reasons map[string]int) string {
	if whitelisted > 0 || len(reasons) == 0 {
		return ""
	}

	// The dominant bucket, with the label as a tie-break so the note is stable between two
	// runs over the same numbers (PERF-041).
	var top string
	var topN int
	for reason, n := range reasons {
		if n > topN || (n == topN && reason < top) {
			top, topN = reason, n
		}
	}

	switch policy.Reason(top) {
	case policy.ReasonListUnavailable:
		return "class_note_unavailable"
	case policy.ReasonNotReality:
		return "class_note_not_reality"
	case policy.ReasonNotInWhitelist, policy.ReasonNoServerName:
		return "class_note_not_listed"
	case policy.ReasonMaskingUnproven:
		return "class_note_unproven"
	default:
		// "classifier not configured" comes from the pipeline rather than from policy, and
		// anything else is a reason added without a note. Both mean the check did not run
		// as designed, which is the louder of the two things this note distinguishes.
		return "class_note_unconfigured"
	}
}

// mixBand orders one distribution largest first and caps it.
//
// The cap is what keeps the band a summary. Countries run to the low tens in a real corpus,
// and a bar chart with forty rows is the node table again with less information in it.
//
// Ties break on the label so the band is byte-stable under regeneration: ranging a Go map is
// deliberately unordered, and a page that reshuffles its own bars between two runs over
// identical data looks like the data moved (PERF-041).
func mixBand(key, testID string, counts map[string]int, limit int) MixBand {
	rows := make([]MixRow, 0, len(counts))
	for label, n := range counts {
		rows = append(rows, MixRow{Label: label, Count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Label < rows[j].Label
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	band := MixBand{Key: key, TestID: testID, Rows: rows, Total: len(counts)}
	if len(rows) > 0 {
		band.Max = rows[0].Count
	}
	return band
}

// buildRows orders and formats the node table.
//
// Best first: longest streak, then lowest latency. A node with no measured latency sorts
// last rather than first — treating an absent measurement as zero would put the nodes we
// know least about at the top of a table whose whole claim is that it is ranked by evidence.
//
// The payload's own order is by identity hash, for byte-stable regeneration (PERF-041), so
// this sorts a copy: a display order must not rewrite what gets published.
func buildRows(nodes []NodeRow) []TableRow {
	// The payload position travels with each row through the display sort, because the card is
	// looked up by position and this function deliberately reorders its copy. A position rather
	// than the display identifier: eight hex characters of a hash can collide across a corpus this
	// size, and a card describing the wrong node is the one mistake this feature must not make.
	type placed struct {
		node NodeRow
		at   int
	}
	ordered := make([]placed, 0, len(nodes))
	for i, n := range nodes {
		ordered = append(ordered, placed{node: n, at: i})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].node.Streak != ordered[j].node.Streak {
			return ordered[i].node.Streak > ordered[j].node.Streak
		}
		li, lj := ordered[i].node.LatencyMS, ordered[j].node.LatencyMS
		if li <= 0 {
			li = math.MaxInt
		}
		if lj <= 0 {
			lj = math.MaxInt
		}
		if li != lj {
			return li < lj
		}
		return ordered[i].node.ID < ordered[j].node.ID
	})

	rows := make([]TableRow, 0, len(ordered))
	for _, o := range ordered {
		n := o.node
		row := TableRow{
			Protocol:  n.Protocol,
			CC:        n.CC,
			Transport: n.Transport,
			ID:        n.ID,
			Masked:    n.Class == "wl",
		}
		// Only a node the payload describes gets a position, so a payload written before the
		// card existed produces a table with no affordance rather than buttons that open nothing.
		if n.Detail != nil {
			row.Node = strconv.Itoa(o.at)
		}
		// Absent is not zero. A failed or skipped measurement renders as an empty cell,
		// because publishing it as 0 ms or 0 Mbps would state a measurement that was
		// never taken (INV-36).
		if n.LatencyMS > 0 {
			row.Latency = strconv.Itoa(n.LatencyMS)
		}
		if n.Mbps > 0 {
			row.Mbps = strconv.FormatFloat(n.Mbps, 'f', 1, 64)
		}
		if n.Streak > 0 {
			row.Streak = strconv.Itoa(n.Streak)
		}
		if !n.VerifiedAt.IsZero() {
			row.Verified = n.VerifiedAt.UTC().Format("02.01 15:04")
		}
		rows = append(rows, row)
	}
	return rows
}

func shortProtocol(p string) string {
	switch p {
	case "shadowsocks":
		return "ss"
	case "hysteria2":
		return "hy2"
	}
	return p
}

// RenderSite writes the page.
//
// html/template is used rather than string substitution because its escaping is contextual:
// a value placed in an attribute, in a script or in text is escaped for that position
// automatically. The predecessor spliced JSON straight into single-quoted attributes with
// no escaping at all, which was reachable from a poisoned artifact (SEC-014).
//
// lang is the document's default language, not its only one: the page carries both, and the
// control swaps an attribute. See siteFuncs.
func RenderSite(w io.Writer, d SiteData, lang string) error {
	// Functions have to be registered before parsing, not after: a template that references
	// an unknown function fails at parse time, and discovering that only when a page is
	// rendered is how a broken build reaches a deploy.
	funcs, err := siteFuncs(lang)
	if err != nil {
		return err
	}

	tpl, err := template.New("page.html").Funcs(funcs).ParseFS(assets,
		"site/page.html", "site/partials/*.html")
	if err != nil {
		return fmt.Errorf("publish: parsing site templates: %w", err)
	}

	// No string table on the payload: every string reaches the template through t, alt or tt,
	// so a key that does not exist fails the render instead of rendering nothing.
	type payload struct {
		SiteData
		Lang string
	}
	return tpl.Execute(w, payload{SiteData: d, Lang: lang})
}

// siteFuncs builds the template function map for one page language.
//
// It is a function of its own so a test can hold it to the one property that matters here: a
// string key that does not exist must abort the render rather than produce an empty label. In
// the predecessor an unfilled token was rewritten to a dash by a safety net that existed
// because a visible one had already shipped (INV-44).
func siteFuncs(lang string) (template.FuncMap, error) {
	words, ok := translations[lang]
	if !ok {
		return nil, fmt.Errorf("publish: no translation for %q", lang)
	}
	other := "en"
	if lang == "en" {
		other = "ru"
	}
	alt := translations[other]
	funcs := templateFuncs()

	// A missing key is an error, not an empty string. In html/template an error from a
	// function aborts the whole render, which is the behaviour INV-44 asks for.
	lookup := func(table map[string]string, key string) (string, error) {
		v, ok := table[key]
		if !ok {
			return "", fmt.Errorf("publish: no string %q in the table", key)
		}
		return v, nil
	}
	// t and alt are for attributes — aria-label, placeholder — which cannot hold two
	// elements. They render the default language and the script exchanges them on switch.
	funcs["t"] = func(key string) (string, error) { return lookup(words, key) }
	funcs["alt"] = func(key string) (string, error) { return lookup(alt, key) }
	// tt is for text, and returns both languages keyed by code. The template renders one
	// element per language and CSS hides the one the document is not currently in, so the
	// first paint never waits on the script. Ranging a map in a template walks it in sorted
	// key order, so the output is byte-stable.
	funcs["tt"] = func(key string) (map[string]string, error) {
		a, err := lookup(words, key)
		if err != nil {
			return nil, err
		}
		b, err := lookup(alt, key)
		if err != nil {
			return nil, err
		}
		return map[string]string{lang: a, other: b}, nil
	}
	funcs["nodeWords"] = func(n int) map[string]string {
		return map[string]string{
			lang:  words[pluralKey(n, lang)],
			other: alt[pluralKey(n, other)],
		}
	}
	return funcs, nil
}

// Asset returns one embedded static file, so the caller can copy it into the output.
func Asset(name string) ([]byte, error) {
	return assets.ReadFile("site/" + name)
}

// AssetNames lists the static files that must be copied alongside the page.
func AssetNames() []string {
	return []string{"assets/site.css", "assets/site.js", "assets/hero.webp"}
}

// RasterAssets lists the asset names that are images, so the byte budget can hold them to
// their own ceiling instead of folding them into the shell's.
func RasterAssets() []string {
	return []string{"assets/hero.webp"}
}

// pluralKey selects the grammatical form for a count.
//
// Russian needs three forms and the rule has an exception in the teens, so "3 узлов" and
// "1 узлов" are what a page gets when the rule is ignored — and that particular wrongness is
// one of the clearest tells that nobody read the output.
func pluralKey(n int, lang string) string {
	if lang != "ru" {
		if n == 1 {
			return "nodes_one"
		}
		return "nodes_many"
	}
	mod100 := n % 100
	if mod100 >= 11 && mod100 <= 14 {
		return "nodes_many"
	}
	switch n % 10 {
	case 1:
		return "nodes_one"
	case 2, 3, 4:
		return "nodes_few"
	}
	return "nodes_many"
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"pct": func(part, whole int) string {
			if whole == 0 {
				return "0.0"
			}
			return fmt.Sprintf("%.1f", float64(part)/float64(whole)*100)
		},
		"comma": func(n int) string { return withThousands(n) },
		"sub":   func(a, b int) int { return a - b },
		// widthClass discretises a proportion into a class name.
		//
		// A strict Content-Security-Policy blocks the style attribute, so a bar cannot carry
		// its own width inline; and setting it from script would leave every bar at zero
		// width for a visitor with JavaScript disabled. Rendering the page loaded under the
		// real policy is what surfaced this — the bars were silently flat.
		//
		// The ladder is finer than 5% below a tenth of the maximum, and that is not
		// cosmetic. A single 5% ladder rounded everything under 2.5% to `w-0`, so in a real
		// corpus — 2960 VLESS against 48 trojan and 37 vmess — the two smallest protocols
		// were drawn as no bar at all: a value present in the data and absent from the mark,
		// in the one element whose whole job is to be the shape of the catalogue. Rounding
		// them *up* to the smallest visible step would have been the other error, stating
		// 5% of the maximum where 1.6% is true, so the small end gets 1% steps instead and
		// any non-zero count keeps at least the 1% one.
		"widthClass": func(part, whole int) string {
			if whole <= 0 || part <= 0 {
				return "w-0"
			}
			pct := float64(part) / float64(whole) * 100
			var step int
			if pct < 10 {
				step = int(pct + 0.5)
				if step < 1 {
					step = 1
				}
			} else {
				step = int(pct/5+0.5) * 5
			}
			if step > 100 {
				step = 100
			}
			return fmt.Sprintf("w-%d", step)
		},
		"round1": func(f float64) string { return fmt.Sprintf("%.1f", f) },
		// freshnessBands lists every band so the readout can carry all of them and let CSS
		// pick. The script then ages the strip by setting one attribute, which is what makes
		// a static page able to say its data is stale — see page.html.
		"freshnessBands": func() []string {
			return []string{FreshnessLive, FreshnessAging, FreshnessStale, FreshnessUnknown}
		},
		// The band edges, in hours, so the client re-bands from the same numbers Go used.
		"freshnessEdge": func(which string) string {
			switch which {
			case "live":
				return strconv.FormatFloat(FreshnessLiveUntil.Hours(), 'f', -1, 64)
			case "aging":
				return strconv.FormatFloat(FreshnessAgingUntil.Hours(), 'f', -1, 64)
			}
			return ""
		},
		// icon inlines one Material Symbol. See icons.go for why the set is inline path data
		// and not a font: this page permits no third-party origin at all.
		"icon": icon,
		// detailSections drives the card's <template>: one block per section, one row per
		// field, labels in both languages.
		"detailSections": detailSections,
		// legalItems lists the notice's statements in order. A slice here rather than a
		// hand-written list in the template so the RU/EN key-coverage test walks the same
		// set the page renders, and an item added without its body is a render error.
		"legalItems": func() []string { return legalItems },
		// legalContactURL is the one route for a takedown or a complaint, and it is a
		// repository URL rather than an address: a page with no route at all cannot claim
		// that well-founded requests are acted on, and an address on a public page both
		// collects spam and ties the project to a person by name.
		"legalContactURL": func() string { return SourcesURL + "/issues" },
	}
}

// withThousands groups digits so a large count is readable at a glance.
func withThousands(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, c)
	}
	return string(out)
}
