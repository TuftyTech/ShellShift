package publish

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"html/template"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/policy"
)

// --- the catalogue mix: one baseline, and no value drawn as nothing ------------------

// ruleBody returns the declarations of the first rule whose selector list contains exactly the
// one asked for.
//
// Exactly, because a substring search for ".bars" also finds ".bars li" and would then assert
// against the wrong block — and a CSS test that silently reads a neighbouring rule passes for
// reasons that have nothing to do with what it claims. First match, so a desktop rule is what a
// caller gets when a narrow-viewport override restates the same selector further down.
func ruleBody(t *testing.T, css, selector string) string {
	t.Helper()
	bodies := ruleBodies(t, css, selector)
	return bodies[0]
}

// ruleBodies returns every rule whose selector list contains exactly the one asked for, in source
// order. The desktop rule is first and a narrow-viewport override is last, which is the only way a
// test can assert that the two compositions stay different on purpose.
func ruleBodies(t *testing.T, css, selector string) []string {
	t.Helper()
	var out []string
	for _, chunk := range strings.Split(css, "}") {
		open := strings.Index(chunk, "{")
		if open < 0 {
			continue
		}
		for _, sel := range strings.Split(chunk[:open], ",") {
			if strings.TrimSpace(sel) == selector {
				out = append(out, chunk[open+1:])
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no rule for %q in the stylesheet", selector)
	}
	return out
}

// heroSize reads the illustration's pixel size out of the WebP header.
//
// Read rather than written down, because the framing rule below is arithmetic over the source's
// aspect ratio: an illustration replaced by one with different proportions must fail this test
// instead of silently re-cropping the band. Only the lossy `VP8 ` form is handled — that is what
// the asset is, and another form should stop the test rather than be guessed at.
func heroSize(t *testing.T) (w, h int) {
	t.Helper()
	b := []byte(readAsset(t, "assets/hero.webp"))
	if len(b) < 30 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WEBP" ||
		string(b[12:16]) != "VP8 " {
		t.Fatal("hero.webp is not a lossy WebP any more; this reader needs updating")
	}
	if b[23] != 0x9d || b[24] != 0x01 || b[25] != 0x2a {
		t.Fatal("no VP8 start code where the header says one should be")
	}
	return int(binary.LittleEndian.Uint16(b[26:28]) & 0x3fff),
		int(binary.LittleEndian.Uint16(b[28:30]) & 0x3fff)
}

// Bars in one band share one set of columns, so two lengths are comparable.
//
// With `display: grid` on each row instead, every row laid out its own three columns and the
// track began wherever that row's own label ended: on a live page `vless` started at 70 px and
// `shadowsocks` at 137 px, both ending at the same right edge, so the two bars encoded their
// values against different baselines and different scales. A chart whose origin moves per row is
// not measuring anything, which is the whole of what a bar is for.
func TestBarsInOneBandShareOneBaseline(t *testing.T) {
	css := stripCSSComments(readAsset(t, "assets/site.css"))

	bars := ruleBody(t, css, ".bars")
	if !strings.Contains(bars, "grid-template-columns:") {
		t.Error(".bars must declare the columns, or each row lays out its own and the " +
			"bar origins differ per row")
	}
	row := ruleBody(t, css, ".bars li")
	if !strings.Contains(row, "grid-template-columns: subgrid") {
		t.Error(".bars li must take its columns from the band with subgrid")
	}
	// The fallback has to come first and be a real column set: a browser without subgrid drops
	// the second declaration, and what it keeps must be the old misalignment rather than three
	// cells stacked on top of each other.
	sub := strings.Index(row, "grid-template-columns: subgrid")
	fallback := strings.Index(row, "grid-template-columns: minmax")
	if fallback < 0 || fallback > sub {
		t.Error(".bars li needs a non-subgrid column declaration before the subgrid one")
	}
	if !strings.Contains(row, "grid-column: 1 / -1") {
		t.Error(".bars li must span the band's columns to subgrid onto them")
	}
}

// A count that exists is drawn. Rounding it away is the one thing this mark may not do.
//
// The ladder used to be 5% steps only, and `int(pct/5+0.5)*5` sends everything under 2.5% to
// `w-0`. On the real corpus that is trojan at 48 and vmess at 37 against a 2960-node maximum:
// two rows with a number printed beside no bar at all, in the element whose job is to be the
// shape of the catalogue. Rounding them up to the smallest visible step would be the opposite
// error — 5% drawn where 1.6% is true — so the small end is stepped at 1%.
func TestASmallShareIsStillDrawn(t *testing.T) {
	widthClass := templateFuncs()["widthClass"].(func(part, whole int) string)
	css := stripCSSComments(readAsset(t, "assets/site.css"))

	// The observed corpus, plus the smallest share that can exist beside it.
	for _, tc := range []struct{ part, whole int }{
		{2960, 2960}, {224, 2960}, {179, 2960}, {48, 2960}, {37, 2960}, {1, 2960}, {1, 100000},
	} {
		class := widthClass(tc.part, tc.whole)
		if class == "w-0" {
			t.Errorf("%d of %d renders as w-0: a value in the data and no mark on the page",
				tc.part, tc.whole)
		}
		if !strings.Contains(css, "."+class+" {") {
			t.Errorf("%d of %d asks for .%s, which the stylesheet does not define",
				tc.part, tc.whole, class)
		}
	}

	// Zero is the one case that must render as nothing, and the floor under .bar-fill must not
	// undo it: a bar for a category with no members is the same lie in the other direction.
	if got := widthClass(0, 2960); got != "w-0" {
		t.Errorf("widthClass(0, 2960) = %q, want w-0", got)
	}
	if !strings.Contains(css, ".bar-fill.w-0 { min-width: 0; }") {
		t.Error("the min-width floor on .bar-fill must be cancelled for w-0")
	}

	// And the mark must stay honest at the small end: 1.6% may not be drawn as 5%.
	if got := widthClass(48, 2960); got != "w-2" {
		t.Errorf("48 of 2960 is 1.6%%, drawn as %q; want w-2", got)
	}
}

// --- the hero framing -----------------------------------------------------------------

// The whole illustration is on screen, at every window width.
//
// Two ways of getting this wrong are already in the history of this rule. `width: 56%` with
// `object-fit: cover` made the cover scale `0.56 · viewport / 900`, so the fraction of the source
// on screen was 45% at 1440 px, 38% at 1720 and 34% at 1920: every extra pixel of window was
// another pixel of zoom. Fixing that with a stated 4:3 box made the crop constant — and constantly
// wrong, because a 4:3 window over a 2:3 source shows exactly half of it, which is why the band
// held a face and nothing else.
//
// The fix is not a nudged `object-position`: it is that the box's aspect ratio equals the
// illustration's own, at which point `cover` crops nothing in either direction and the framing is
// the illustration's own framing. The band's height then carries the scale, so it is the band that
// follows the monitor.
func TestTheWholeIllustrationIsShown(t *testing.T) {
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	art := ruleBody(t, css, ".hero-art")
	srcW, srcH := heroSize(t)

	if !strings.Contains(art, "height: 100%") {
		t.Error(".hero-art must be sized from the band's height")
	}
	// A percentage width puts the viewport back into the cover scale, which is the first of the
	// two defects above. A percentage max-width is a different thing: it only ever narrows the
	// box on a small window, never deepens the zoom.
	if regexp.MustCompile(`(^|[;{\s])width:\s*\d+%`).MatchString(art) {
		t.Error(".hero-art must not take a percentage width: that is the viewport in the " +
			"cover scale again")
	}
	if !strings.Contains(art, "max-width:") {
		t.Error(".hero-art needs a max-width, or the art can swallow the copy column")
	}

	// The arithmetic. Under `cover` the image is scaled by max(boxW/srcW, boxH/srcH), so the
	// visible fraction of each dimension is 1 only when the two ratios agree.
	m := regexp.MustCompile(`aspect-ratio:\s*([0-9.]+)\s*/\s*([0-9.]+)`).FindStringSubmatch(art)
	if m == nil {
		t.Fatal(".hero-art needs a stated aspect-ratio: without one the box has no width that " +
			"is independent of the viewport")
	}
	boxW, _ := strconv.ParseFloat(m[1], 64)
	boxH, _ := strconv.ParseFloat(m[2], 64)
	rBox, rSrc := boxH/boxW, float64(srcH)/float64(srcW)
	visibleH := math.Min(1, rBox/rSrc)
	visibleW := math.Min(1, rSrc/rBox)
	if visibleH < 0.995 || visibleW < 0.995 {
		t.Errorf("a %g/%g box over a %dx%d source shows %.0f%% of its height and %.0f%% of its "+
			"width; the ratios must agree so that cover crops nothing",
			boxW, boxH, srcW, srcH, visibleH*100, visibleW*100)
	}

	// And the band's height is what follows the monitor, within stated bounds: a floor so the
	// figure does not collapse on a laptop, a ceiling so the band cannot eat the fold. The height
	// sits on `.hero-body`, the grid inside the band, because that is the element the copy column
	// and the art share.
	hero := ruleBody(t, css, ".hero-body")
	band := regexp.MustCompile(
		`min-height:\s*clamp\(\s*([0-9.]+)rem\s*,(.+),\s*([0-9.]+)rem\s*\)`).
		FindStringSubmatch(hero)
	if band == nil {
		t.Fatal(".hero needs min-height: clamp(<floor>rem, <viewport term>, <ceiling>rem) — a " +
			"constant band height is what made the art's size a property of nothing")
	}
	if !strings.Contains(band[2], "vw") {
		t.Errorf("the band's preferred height is %q and names no vw: then the illustration is "+
			"the same size on a laptop and on a 4K display", strings.TrimSpace(band[2]))
	}
	floor, _ := strconv.ParseFloat(band[1], 64)
	ceiling, _ := strconv.ParseFloat(band[3], 64)
	if floor < 24 {
		t.Errorf("band floor %grem is too short for the figure to read", floor)
	}
	if ceiling > 52 {
		t.Errorf("band ceiling %grem eats the fold on any normal display", ceiling)
	}
	t.Logf("the band runs %g..%grem and the art is %.2f of its height wide, so the figure is "+
		"%.0f..%.0f px tall", floor, ceiling, 1/rBox, floor*16, ceiling*16)

	// The narrow viewport is a different composition on purpose: there the art covers the whole
	// band behind the copy, because a 2:3 portrait shown whole at 390 px wide would demand a
	// 585 px band of a 780 px screen.
	bodies := ruleBodies(t, css, ".hero-art")
	if len(bodies) < 2 {
		t.Fatal("the narrow-viewport override for .hero-art is gone")
	}
	narrow := bodies[len(bodies)-1]
	if !strings.Contains(narrow, "object-fit: cover") || !strings.Contains(narrow, "width: 100%") {
		t.Error("the narrow override must still cover the band edge to edge")
	}
	if !strings.Contains(narrow, "aspect-ratio: auto") {
		t.Error("the override must retire the aspect-ratio box, or both dimensions fight")
	}
}

// --- the node table's legend ----------------------------------------------------------

// The legend describes the table it sits under, and only that.
//
// Rendered unconditionally it explained a WL marker and a second line in the latency column in a
// run that had neither: no whitelisted node, because the whitelist feed had not loaded, and no
// throughput, because measuring it is off by default. So the one paragraph on the page whose job
// is to decode the markup was pointing at markup that was not on the page.
func TestTheLegendDescribesTheTableItSitsUnder(t *testing.T) {
	t.Run("both markers present", func(t *testing.T) {
		html := render(t, fixtureData(t), "ru", time.Now())
		if !strings.Contains(html, `data-testid="node-legend"`) {
			t.Fatal("the fixture has a wl node and a measured throughput; the legend must render")
		}
		if !strings.Contains(html, "WL —") {
			t.Error("the legend must decode the WL marker when a row carries it")
		}
		if !strings.Contains(html, "Мбит/с") {
			t.Error("the legend must decode the second latency line when a row carries it")
		}
	})

	t.Run("neither marker present", func(t *testing.T) {
		d := fixtureData(t)
		for i := range d.Nodes {
			d.Nodes[i].Class = "open"
			d.Nodes[i].Mbps = 0
		}
		html := render(t, d, "ru", time.Now())
		if strings.Contains(html, `data-testid="node-legend"`) {
			t.Error("no row carries either marker, so there is nothing to decode")
		}
	})

	t.Run("only the masking marker", func(t *testing.T) {
		d := fixtureData(t)
		for i := range d.Nodes {
			d.Nodes[i].Mbps = 0
		}
		html := render(t, d, "ru", time.Now())
		if !strings.Contains(html, "WL —") {
			t.Error("a wl row is present, so WL must be explained")
		}
		if strings.Contains(html, "Мбит/с") {
			t.Error("no throughput was measured, so the second line must not be explained")
		}
	})
}

// --- an empty class, and which of the two things it means ------------------------------

// onPage reports whether a string from the table is in the rendered document.
//
// Comparing the raw table entry fails on every string containing an apostrophe — "the user's",
// "somebody else's server" — because html/template writes it as &#39;, and a test that looks for
// the unescaped form reports the string as absent from a page that carries it. The difference is
// invisible in a diff, which is what makes it worth a named helper rather than a note.
func onPage(html, s string) bool { return strings.Contains(html, template.HTMLEscapeString(s)) }

// A class with no members says why it has none.
//
// "whitelisted — 0 узлов" is the same number whether no node qualified or the whitelist feed
// never loaded and the check never ran, and those are opposite facts: one is the shape of the
// catalogue, the other is a broken run. The histogram that separates them has been in the run
// report since the beginning and publication threw it away, so the page — the only surface
// anybody looks at — was the one place it could not be read.
func TestAnEmptyClassSaysWhyItIsEmpty(t *testing.T) {
	// Every reason the classifier can return, and the note it must produce. The switch in
	// classNote is on policy.Reason so that renaming a reason is a compile error; this table is
	// the other half of it, because a reason added with no note falls through to the
	// "not configured" wording and would tell a reader the check never ran when it did.
	for _, tc := range []struct {
		reason policy.Reason
		want   string
	}{
		{policy.ReasonListUnavailable, "class_note_unavailable"},
		{policy.ReasonNotReality, "class_note_not_reality"},
		{policy.ReasonNotInWhitelist, "class_note_not_listed"},
		{policy.ReasonNoServerName, "class_note_not_listed"},
		{policy.ReasonMaskingUnproven, "class_note_unproven"},
		// Not a policy.Reason: the pipeline writes this one itself when no classifier was
		// configured at all.
		{policy.Reason("classifier not configured"), "class_note_unconfigured"},
		{policy.Reason("a reason added without a note"), "class_note_unconfigured"},
	} {
		got := classNote(0, map[string]int{string(tc.reason): 7})
		if got != tc.want {
			t.Errorf("reason %q produced note %q, want %q", tc.reason, got, tc.want)
		}
		for _, lang := range Languages {
			if translations[lang][got] == "" {
				t.Errorf("note %q (reason %q) is missing from the %s table", got, tc.reason, lang)
			}
		}
	}

	// A class with members needs no note: the count is the whole statement.
	if got := classNote(4, map[string]int{string(policy.ReasonWhitelisted): 4}); got != "" {
		t.Errorf("a populated class produced the note %q", got)
	}
	// With no histogram there is nothing to say, and saying the vaguest thing anyway would be
	// the predecessor's "UN" — a value invented at the display layer and then believed.
	if got := classNote(0, nil); got != "" {
		t.Errorf("no reasons produced the note %q", got)
	}

	// Two reasons tied on count must resolve the same way every time, or the card's wording
	// changes between two runs over identical numbers (PERF-041).
	tied := map[string]int{
		string(policy.ReasonNotReality):     5,
		string(policy.ReasonNotInWhitelist): 5,
	}
	first := classNote(0, tied)
	for i := 0; i < 16; i++ {
		if got := classNote(0, tied); got != first {
			t.Fatalf("a tie resolved to %q and then to %q", first, got)
		}
	}
}

// The note reaches the card, and only the card that is empty.
func TestTheEmptyClassCardCarriesTheNote(t *testing.T) {
	d := fixtureData(t)
	for i := range d.Nodes {
		d.Nodes[i].Class = "open"
	}
	d.ClassReasons = map[string]int{string(policy.ReasonListUnavailable): len(d.Nodes)}

	html := render(t, d, "ru", d.GeneratedAt)
	if !strings.Contains(html, `data-testid="endpoint-why"`) {
		t.Fatal("no node is whitelisted and the run said why; the card must carry the note")
	}
	for _, lang := range Languages {
		if !onPage(html, translations[lang]["class_note_unavailable"]) {
			t.Errorf("the %s wording of the note is not on the page", lang)
		}
	}

	// The fixture's first node is whitelisted, so the class has a member and explains nothing.
	populated := fixtureData(t)
	populated.ClassReasons = map[string]int{string(policy.ReasonListUnavailable): 2}
	if strings.Contains(render(t, populated, "ru", d.GeneratedAt), `data-testid="endpoint-why"`) {
		t.Error("a class with a member must not explain why it is empty")
	}

	// The note has to survive publication. `shellshift site -data dist/network.json` renders
	// the page from a payload rather than from a live run, and the histogram is `omitempty`:
	// dropped there, the card would explain itself on the run that produced it and stop doing
	// so on every rebuild from the same data.
	var payload bytes.Buffer
	if err := WriteData(&payload, d); err != nil {
		t.Fatalf("write: %v", err)
	}
	var back Data
	if err := json.Unmarshal(payload.Bytes(), &back); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(back.ClassReasons) != len(d.ClassReasons) {
		t.Fatalf("reasons after a round trip = %v, want %v", back.ClassReasons, d.ClassReasons)
	}
	if !strings.Contains(render(t, back, "ru", d.GeneratedAt), `data-testid="endpoint-why"`) {
		t.Error("the note does not survive the payload the site command is given")
	}

	// The dimming is on the head and the field, not on the card: an empty card used to fade
	// the one paragraph a reader most needs to read.
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	if strings.Contains(css, ".ep-empty {") {
		t.Error(".ep-empty must not dim the whole card, or it dims the note explaining it")
	}
	if !strings.Contains(css, ".ep-empty .ep-head") {
		t.Error("the empty state must dim the head and the field by name")
	}
}

// --- what each subscription holds -----------------------------------------------------

// Every card says what its file contains, and the cards in a row are the same height.
//
// Two of the seven had a note and five did not, which made the band look broken: a row whose left
// card carried three lines of explanation and whose right card carried none left a ragged hole,
// and the reader's first question about `vless` versus `all` went unanswered anyway. The titles
// are not self-explanatory to anyone who does not already know the protocols — which is most of
// the people a subscription file is for.
func TestEveryCardSaysWhatItHolds(t *testing.T) {
	for _, b := range Bundles() {
		note, ok := bundleNotes[b.Name]
		if !ok {
			t.Errorf("%s has no note: a card with a title and no sentence is a guess", b.Name)
			continue
		}
		for _, lang := range Languages {
			if translations[lang][note] == "" {
				t.Errorf("note %q for %s is missing from the %s table", note, b.Name, lang)
			}
		}
	}
	names := map[string]bool{}
	for _, b := range Bundles() {
		names[b.Name] = true
	}
	for name := range bundleNotes {
		if !names[name] {
			t.Errorf("bundleNotes describes %q, which is not a bundle", name)
		}
	}

	html := render(t, fixtureData(t), "ru", time.Now())
	if got, want := strings.Count(html, `data-testid="endpoint-note"`), len(Bundles()); got != want {
		t.Errorf("%d notes rendered for %d cards", got, want)
	}
	for name, note := range bundleNotes {
		for _, lang := range Languages {
			if !onPage(html, translations[lang][note]) {
				t.Errorf("the %s note for %s is not on the page", lang, name)
			}
		}
	}

	// Equal heights, and the note at the foot of the card. Without the row track every card is
	// as tall as its own text, which is the ragged band this test exists to close; without the
	// flex column there is nothing for `margin-top: auto` to push against.
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	list := ruleBody(t, css, ".ep-list")
	if !strings.Contains(list, "grid-auto-rows: 1fr") {
		t.Error(".ep-list must give its rows one height, or cards in a row are ragged")
	}
	card := ruleBody(t, css, ".ep")
	if !strings.Contains(card, "display: flex") || !strings.Contains(card, "flex-direction: column") {
		t.Error(".ep must be a flex column for the note to sit at the foot")
	}
	note := ruleBody(t, css, ".ep-note")
	if !strings.Contains(note, "margin-top: auto") {
		t.Error(".ep-note must be pushed to the foot of the card")
	}
}

// --- the legal notice -------------------------------------------------------------------

// Every statement in the notice exists in both languages, heading and body.
//
// The keys are built with printf from a slice in Go, so the regex in
// TestEveryTemplateKeyExistsInBothLanguages — which scans the templates for literal `tt "key"` —
// cannot see them. A statement added in Russian and forgotten in English is the one failure a
// bilingual legal notice must not have: it would abort the render of the whole page at the next
// run, and the missing half is a claim the project is making in one language only.
func TestTheLegalNoticeIsCompleteInBothLanguages(t *testing.T) {
	if len(legalItems) < 5 {
		t.Fatalf("%d statements; the notice is too thin to be one", len(legalItems))
	}
	seen := map[string]bool{}
	for _, item := range legalItems {
		if seen[item] {
			t.Errorf("%q is listed twice", item)
		}
		seen[item] = true
		for _, lang := range Languages {
			if translations[lang][item] == "" {
				t.Errorf("heading %q is missing from the %s table", item, lang)
			}
			body := item + "_body"
			if translations[lang][body] == "" {
				t.Errorf("body %q is missing from the %s table", body, lang)
			}
		}
	}
	for _, key := range []string{"legal", "legal_lede", "legal_not_advice"} {
		for _, lang := range Languages {
			if translations[lang][key] == "" {
				t.Errorf("%q is missing from the %s table", key, lang)
			}
		}
	}

	html := render(t, fixtureData(t), "ru", time.Now())
	if !strings.Contains(html, `data-testid="legal-list"`) {
		t.Fatal("the notice does not render")
	}
	for _, item := range legalItems {
		for _, lang := range Languages {
			if !onPage(html, translations[lang][item+"_body"]) {
				t.Errorf("the %s body of %q is not on the page", lang, item)
			}
		}
	}

	// The notice states its own limit. A disclaimer that does not say what it cannot do is
	// where a dispute starts, so the caveat is part of the notice rather than an option.
	if !strings.Contains(html, `data-testid="legal-not-advice"`) {
		t.Error("the notice must carry its own limit")
	}

	// One route to act on, and it is a repository URL: a page with no route cannot claim that
	// well-founded requests are acted on, and an address ties the project to a person.
	if !strings.Contains(html, SourcesURL+"/issues") {
		t.Error("the takedown route is not on the page")
	}

	// Last in the document, and after the inventory it qualifies. It is reference material:
	// nobody arrives for it, and the predecessor's version of these statements was scattered
	// between a hero caveat and a footer line, which is how a page ends up making a claim
	// nothing on it qualifies.
	legal := strings.Index(html, `id="legal"`)
	for _, before := range []string{`id="subs"`, `id="nodes"`, `id="howto"`} {
		if at := strings.Index(html, before); at < 0 || at > legal {
			t.Errorf("%s is not before the notice", before)
		}
	}

	// The order inside it is not arbitrary: what the project is comes before what it is not
	// liable for, so a reader who stops after two items has read the two that matter.
	if legalItems[0] != "legal_role" || legalItems[1] != "legal_source" {
		t.Errorf("the notice opens with %q, %q; it must open with what the project is and "+
			"where the data came from", legalItems[0], legalItems[1])
	}
	if a, b := strings.Index(html, template.HTMLEscapeString(translations["ru"]["legal_role_body"])),
		strings.Index(html, template.HTMLEscapeString(translations["ru"]["legal_marks_body"])); a > b {
		t.Error("the rendered order does not follow legalItems")
	}
}

// --- the readout, which has to be able to say the pipeline stopped ----------------------

// A page rendered at 04:38 said "0.0ч назад · свежие данные" for as long as it was served.
//
// The one element whose purpose is to report a stopped pipeline was the one element that could
// never report one: the age was computed at build time and baked in, so it stayed zero while the
// pipeline was down. The absolute timestamp beside it was correct the whole time, which is what
// makes the pair unreadable rather than merely stale.
//
// The fix is that every band ships in the markup, CSS shows the one the container names, and the
// script re-bands from the timestamp — so a visitor with the script blocked still sees the band
// the run was rendered with, and everyone else sees the truth.
func TestTheStaleBandIsReachableWithoutARebuild(t *testing.T) {
	d := fixtureData(t)
	html := render(t, d, "ru", d.GeneratedAt) // rendered fresh: age zero
	if !strings.Contains(html, `data-freshness="live"`) {
		t.Fatal("a page rendered at its own timestamp is live")
	}
	for _, band := range []string{FreshnessLive, FreshnessAging, FreshnessStale, FreshnessUnknown} {
		if !strings.Contains(html, `data-band="`+band+`"`) {
			t.Errorf("band %q is not in the markup, so the script cannot reach it", band)
		}
		for _, lang := range Languages {
			if !onPage(html, translations[lang]["freshness_"+band]) {
				t.Errorf("the %s wording of band %q is not on the page", lang, band)
			}
		}
	}

	// Only one is visible, and that is CSS rather than script: without the hiding rule the
	// strip reads "свежие данные устаревают устарели неизвестно" in one line.
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	if !strings.Contains(css, ".readout [data-band] { display: none; }") {
		t.Error("every band is in the markup and nothing hides the three that do not apply")
	}
	for _, band := range []string{FreshnessLive, FreshnessAging, FreshnessStale, FreshnessUnknown} {
		rule := `.readout[data-freshness="` + band + `"] [data-band="` + band + `"]`
		if !strings.Contains(css, rule) {
			t.Errorf("no rule shows band %q when the container names it", band)
		}
	}

	// The edges are rendered from the Go constants and read back by the script. A second copy
	// of "five hours" inside site.js would be a threshold that could drift from this one with
	// nothing in the tree to notice.
	for attr, want := range map[string]time.Duration{
		"data-live-hours":  FreshnessLiveUntil,
		"data-aging-hours": FreshnessAgingUntil,
	} {
		pair := attr + `="` + strconv.FormatFloat(want.Hours(), 'f', -1, 64) + `"`
		if !strings.Contains(html, pair) {
			t.Errorf("the readout does not carry %s", pair)
		}
	}
	js := readAsset(t, "assets/site.js")
	for _, attr := range []string{"data-live-hours", "data-aging-hours"} {
		if !strings.Contains(js, attr) {
			t.Errorf("the script does not read %s, so it has its own copy of the threshold", attr)
		}
	}

	// The absolute stamp is a date and nothing more. A clock printed beside a relative age is
	// two readings of the same fact at different precisions, and the one the reader can act on
	// is the age — "22:55Z" only invites the arithmetic the line beside it has already done.
	// The exact instant stays in the attribute, because that is what the script reads.
	stamp := regexp.MustCompile(`data-testid="heartbeat-absolute">([^<]*)<`).FindStringSubmatch(html)
	if stamp == nil {
		t.Fatal("the readout has no absolute stamp")
	}
	if regexp.MustCompile(`\d\d:\d\d`).MatchString(stamp[1]) {
		t.Errorf("the stamp reads %q and still prints a clock", stamp[1])
	}
	if want := d.GeneratedAt.UTC().Format("2006-01-02"); strings.TrimSpace(stamp[1]) != want {
		t.Errorf("the stamp reads %q, want the date %q", stamp[1], want)
	}
	if !strings.Contains(html, `data-verified-at="`+d.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")+`"`) {
		t.Error("the exact instant must stay in data-verified-at: the script ages the page from it")
	}

	// The figure is its own element, and the unit is bilingual like every other string: with
	// the unit inside the same node the script would have to rewrite "0.0ч назад" as a whole,
	// and rendered through `t` it stayed "ч назад" after a switch to English.
	if !strings.Contains(html, `data-testid="heartbeat-age"`) {
		t.Error("the age has no element of its own for the script to update")
	}
	for _, lang := range Languages {
		if !onPage(html, translations[lang]["ago_hours"]) {
			t.Errorf("the %s unit is not in the document", lang)
		}
	}

	// And the band Go picks still follows the timestamp, at both edges.
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{FreshnessLiveUntil - time.Minute, FreshnessLive},
		{FreshnessLiveUntil + time.Minute, FreshnessAging},
		{FreshnessAgingUntil + time.Minute, FreshnessStale},
	} {
		if got := render(t, d, "ru", d.GeneratedAt.Add(tc.age)); !strings.Contains(got,
			`data-freshness="`+tc.want+`"`) {
			t.Errorf("age %v did not render as %s", tc.age, tc.want)
		}
	}
}

// --- the keys the template scanner cannot see -------------------------------------------

// Every string named from Go rather than written in a template exists in both languages.
//
// TestEveryTemplateKeyExistsInBothLanguages scans the templates for a literal `tt "key"`, which
// is the whole set as long as the templates name their strings. These do not: the notice, the
// bundle notes, the class notes and the freshness bands are all built with printf or looked up
// from a map. Only one class note is reachable per run, so four of the five would first be tested
// by a live run — and a missing one aborts the render of the entire page, which means a run that
// verified a catalogue publishes nothing.
func TestStringsNamedFromGoExistInBothLanguages(t *testing.T) {
	keys := map[string]string{}
	for _, item := range legalItems {
		keys[item] = "a legal heading"
		keys[item+"_body"] = "a legal body"
	}
	for name, note := range bundleNotes {
		keys[note] = "the note for " + name
	}
	for _, reason := range []policy.Reason{
		policy.ReasonListUnavailable, policy.ReasonNotReality, policy.ReasonNotInWhitelist,
		policy.ReasonNoServerName, policy.ReasonMaskingUnproven,
		policy.Reason("classifier not configured"),
	} {
		keys[classNote(0, map[string]int{string(reason): 1})] = "the note for " + string(reason)
	}
	for _, band := range templateFuncs()["freshnessBands"].(func() []string)() {
		keys["freshness_"+band] = "the " + band + " band"
	}
	for _, key := range []string{"legal", "legal_lede", "legal_not_advice", "ago_hours"} {
		keys[key] = "part of the readout or the notice"
	}

	if len(keys) < 25 {
		t.Fatalf("only %d keys collected; the scan is not finding them", len(keys))
	}
	for key, what := range keys {
		for _, lang := range Languages {
			if _, ok := translations[lang][key]; !ok {
				t.Errorf("%s (%q) is missing from the %s table", what, key, lang)
			}
		}
	}
}
