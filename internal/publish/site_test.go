package publish

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"
)

func fixtureData(t *testing.T) Data {
	t.Helper()
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	return Data{
		Version:     DataVersion,
		GeneratedAt: at,
		RunSeconds:  109.4,
		Engine:      "sing-box/1.13.19 (in-process)",
		// The figures balance under INV-40: a fixture that could not have come from a real
		// run is not a fixture, and TestFixtureFunnelBalances holds it to that.
		Funnel: Funnel{
			Collected: 14314, Rejected: 1897, Decoded: 12417, Duplicates: 1217,
			Candidates: 11200, Policy: 10539, Reached: 4135, Failed: 10507, Proven: 693,
		},
		// The third node has no latency, no throughput and no streak on purpose: an absent
		// measurement must render as an empty cell and never as a zero (INV-36).
		Nodes: []NodeRow{
			{ID: "aa11bb22", CC: "NL", Protocol: "vless", Transport: "tcp", Class: "wl",
				LatencyMS: 120, Mbps: 18.4, Streak: 12, VerifiedAt: at},
			{ID: "cc33dd44", CC: "DE", Protocol: "trojan", Transport: "ws", Class: "open",
				LatencyMS: 240, Streak: 3, VerifiedAt: at},
			{ID: "ee55ff66", CC: "NL", Protocol: "shadowsocks", Transport: "tcp", Class: "open",
				VerifiedAt: at},
		},
	}
}

func render(t *testing.T, d Data, lang string, now time.Time) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSite(&buf, BuildSiteData(d, "https://example.github.io/ShellShift", now), lang); err != nil {
		t.Fatalf("render %s: %v", lang, err)
	}
	return buf.String()
}

// emptyCatalogue is the page before any node exists: chrome, and nothing that scales with a
// corpus. It is what the chrome budget is measured against.
func emptyCatalogue(t *testing.T) Data {
	t.Helper()
	d := fixtureData(t)
	d.Nodes = nil
	// Still balanced under INV-40: a fixture that could not have come from a real run teaches
	// the renderer to display an impossible funnel.
	d.Funnel = Funnel{
		Collected: 1200, Rejected: 300, Decoded: 900, Duplicates: 100,
		Candidates: 800, Policy: 700, Reached: 0, Failed: 800, Proven: 0,
	}
	return d
}

// withNodes is the same payload carrying n synthetic rows, for measuring what one row costs.
func withNodes(t *testing.T, n int) Data {
	t.Helper()
	d := fixtureData(t)
	rows := make([]NodeRow, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, NodeRow{
			ID: fmt.Sprintf("%08x", i), CC: "NL", Protocol: "vless", Transport: "tcp",
			Class: "wl", LatencyMS: 100 + i, Mbps: 12.5, Streak: 4, VerifiedAt: d.GeneratedAt,
		})
	}
	d.Nodes = rows
	return d
}

// INV-44. A template that fails to render must fail loudly. The predecessor wrapped its page
// build in one except that logged and left the previous page in place, with a green log, and had
// a safety net rewriting unfilled tokens to a dash because a visible one had already shipped.
func TestBothLanguagesRender(t *testing.T) {
	d := fixtureData(t)
	for _, lang := range Languages {
		t.Run(lang, func(t *testing.T) {
			html := render(t, d, lang, d.GeneratedAt.Add(time.Hour))
			if !strings.Contains(html, `lang="`+lang+`"`) {
				t.Fatalf("page does not declare its language")
			}
			// No token may survive into the output.
			for _, leftover := range []string{"{{", "}}", "%!", "<no value>"} {
				if strings.Contains(html, leftover) {
					t.Fatalf("unrendered template artefact %q in output", leftover)
				}
			}
		})
	}
}

// An unknown locale is an error rather than a silently English page.
func TestUnknownLanguageIsAnError(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderSite(&buf, BuildSiteData(fixtureData(t), "", time.Now()), "fr"); err == nil {
		t.Fatal("an unknown locale must be refused")
	}
}

// The funnel is the signature element and must carry real numbers, including what each stage
// discarded.
func TestFunnelRendersRealNumbers(t *testing.T) {
	html := render(t, fixtureData(t), "en", time.Now())
	for _, want := range []string{
		`data-stage="collected" data-value="14314"`,
		`data-stage="proven" data-value="693"`,
		`data-testid="funnel-method"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("funnel missing %s", want)
		}
	}
	// The drop between stages is shown, not just the survivors.
	if !strings.Contains(html, "1 897") {
		t.Fatalf("the decode drop is not rendered:\n%s", firstLines(html, 60))
	}
	// Deduplication removes real work, so the stage and its drop are both on the page. A
	// funnel that steps from decoded straight to policy attributes that drop to nothing.
	for _, want := range []string{
		`data-stage="candidates" data-value="11200"`,
		"1 217",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("the deduplication stage is missing %s:\n%s", want, firstLines(html, 60))
		}
	}
}

// INV-40. The numbers the page renders must be numbers a run could have produced. A fixture
// that does not balance teaches the renderer to display an impossible funnel.
func TestFixtureFunnelBalances(t *testing.T) {
	f := fixtureData(t).Funnel
	if n := f.Unaccounted(); n != 0 {
		t.Fatalf("the fixture funnel leaves %+d of %d lines unaccounted for", n, f.Collected)
	}
	if f.Candidates != f.Decoded-f.Duplicates {
		t.Fatalf("candidates = %d, want decoded(%d) - duplicates(%d)",
			f.Candidates, f.Decoded, f.Duplicates)
	}
}

// The predecessor rendered a pulsing "active" badge unconditionally, with no data binding, so
// a pipeline dead for two days still claimed to be running.
func TestFreshnessIsBoundToTheTimestamp(t *testing.T) {
	d := fixtureData(t)
	cases := []struct {
		age  time.Duration
		want string
	}{
		{2 * time.Hour, FreshnessLive},
		{4 * time.Hour, FreshnessAging},
		{30 * time.Hour, FreshnessStale},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			html := render(t, d, "ru", d.GeneratedAt.Add(tc.age))
			if !strings.Contains(html, `data-freshness="`+tc.want+`"`) {
				t.Fatalf("age %v did not render as %s", tc.age, tc.want)
			}
		})
	}

	// No timestamp at all is its own state, not a claim of freshness.
	empty := d
	empty.GeneratedAt = time.Time{}
	html := render(t, empty, "ru", time.Now())
	if !strings.Contains(html, `data-freshness="unknown"`) {
		t.Fatal("a missing timestamp must render as unknown")
	}
}

// SEC-014 and SEC-015. Contextual escaping and a policy that a page on a host which cannot
// set headers still gets.
func TestPageCarriesAPolicyAndEscapesValues(t *testing.T) {
	d := fixtureData(t)
	// A hostile country code is the shape a poisoned artifact would take.
	d.Nodes[0].CC = `"><script>alert(1)</script>`

	html := render(t, d, "en", time.Now())
	if strings.Contains(html, "<script>alert(1)") {
		t.Fatalf("value was not escaped:\n%s", firstLines(html, 40))
	}
	if !strings.Contains(html, "Content-Security-Policy") {
		t.Fatal("the page must carry a policy: the host cannot set headers")
	}
	// WCAG 1.4.4: the predecessor disabled pinch zoom.
	if strings.Contains(html, "user-scalable=no") || strings.Contains(html, "maximum-scale") {
		t.Fatal("pinch zoom must not be disabled")
	}
}

// A run that could not finish must say so on the page, because the yield it shows is a floor
// rather than a measurement.
func TestBudgetWarningIsShown(t *testing.T) {
	d := fixtureData(t)
	if strings.Contains(render(t, d, "ru", time.Now()), `data-testid="budget-warning"`) {
		t.Fatal("the warning must not appear when the run completed")
	}
	d.Funnel.BudgetExhausted = true
	if !strings.Contains(render(t, d, "ru", time.Now()), `data-testid="budget-warning"`) {
		t.Fatal("the warning must appear when the run ran out of budget")
	}
}

// An empty catalogue is a designed state, not zero-width bars and dashes. The predecessor
// returned early from its stats code and left every bar at zero with no explanation.
func TestEmptyCatalogueHasADesignedState(t *testing.T) {
	d := fixtureData(t)
	d.Nodes = nil
	d.Funnel = Funnel{Collected: 1200, Decoded: 900}

	html := render(t, d, "ru", time.Now())
	if !strings.Contains(html, `data-testid="endpoints-empty"`) {
		t.Fatal("an empty catalogue must render its own state")
	}
	if strings.Contains(html, `data-testid="endpoint-card"`) {
		t.Fatal("no endpoint cards should be offered when there is nothing to subscribe to")
	}
}

// The subscription URL is visible text rather than a value hidden behind a button, so a
// failed clipboard degrades to selecting it.
func TestSubscriptionURLsAreVisible(t *testing.T) {
	html := render(t, fixtureData(t), "en", time.Now())
	if !strings.Contains(html, `value="https://example.github.io/ShellShift/sub_all.txt"`) {
		t.Fatalf("the subscription URL must be visible text:\n%s", firstLines(html, 80))
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// Russian needs three plural forms with an exception in the teens. "3 узлов" and "1 узлов"
// are what a page gets when the rule is ignored, and that particular wrongness is one of the
// clearest signs nobody read the output.
func TestRussianPluralForms(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{1, "узел"}, {2, "узла"}, {4, "узла"}, {5, "узлов"}, {0, "узлов"},
		{11, "узлов"}, {12, "узлов"}, {14, "узлов"}, {21, "узел"}, {22, "узла"},
		{101, "узел"}, {111, "узлов"}, {693, "узла"},
	}
	for _, tc := range cases {
		if got := translations["ru"][pluralKey(tc.n, "ru")]; got != tc.want {
			t.Errorf("%d -> %q, want %q", tc.n, got, tc.want)
		}
	}
	if got := translations["en"][pluralKey(1, "en")]; got != "node" {
		t.Errorf("english singular = %q", got)
	}
	if got := translations["en"][pluralKey(2, "en")]; got != "nodes" {
		t.Errorf("english plural = %q", got)
	}
}

// A list with nothing in it must not offer a subscription: a visitor who copies it gets an
// empty file and blames the configurations rather than the page.
func TestEmptyBundleDoesNotOfferCopying(t *testing.T) {
	d := fixtureData(t)
	// The fixture has no hysteria2 node, so that bundle is empty.
	html := render(t, d, "ru", time.Now())
	idx := strings.Index(html, `data-endpoint="sub_hy2.txt"`)
	if idx < 0 {
		t.Fatal("the hysteria2 bundle should still be listed")
	}
	card := html[idx:]
	if end := strings.Index(card, "</li>"); end > 0 {
		card = card[:end]
	}
	if !strings.Contains(card, "disabled") {
		t.Fatalf("an empty bundle must not offer a working copy button:\n%s", card)
	}
}

// The controls in the bar carry an icon and a name that is not the icon. An icon alone is not a
// label: the predecessor's theme control was a lone glyph, which is unreadable to a screen
// reader and ambiguous to everyone else.
func TestBarControlsCarryIconsAndNames(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())

	theme := elementAt(html, `data-testid="theme-toggle"`)
	if !strings.Contains(theme, "<svg") {
		t.Errorf("the theme control has no icon:\n%s", theme)
	}
	if !strings.Contains(theme, "aria-label=") {
		t.Errorf("the theme control has no accessible name:\n%s", theme)
	}
	// The glyph the icon replaced. It is asserted absent so a revert is a test failure rather
	// than a silent regression in typeface support.
	if strings.Contains(html, "◐") {
		t.Error("the theme control must not fall back to a text glyph")
	}

	// Both languages are offered, and the current one is marked as current rather than simply
	// omitted. A visitor who cannot read this page's language must still see the other exists.
	if !strings.Contains(html, `aria-current="page"`) {
		t.Error("the language control does not mark the current language")
	}
	if !strings.Contains(html, `data-testid="lang-toggle"`) {
		t.Error("the language control does not offer the other language")
	}
}

// The copy button's label is its own element, and this is the regression guard for why: the
// button holds two icons, and rewriting the button's textContent to say "copied" — which is what
// the script used to do — removes them both.
func TestCopyButtonLabelIsItsOwnElement(t *testing.T) {
	html := render(t, fixtureData(t), "en", time.Now())
	btn := elementAt(html, `data-testid="endpoint-copy"`)
	if !strings.Contains(btn, `data-testid="endpoint-copy-label"`) {
		t.Fatalf("the copy label must be its own element:\n%s", btn)
	}
	if !strings.Contains(btn, `class="i i-copy"`) || !strings.Contains(btn, `class="i i-check"`) {
		t.Fatalf("the copy button must carry both state icons:\n%s", btn)
	}

	// The assignment, not the mention: the script's own comment explains why it does not do
	// this, and a gate that fired on the explanation would be answered by deleting it.
	script := readAsset(t, "assets/site.js")
	if strings.Contains(script, "btn.textContent =") {
		t.Error("the script must not assign to the button's textContent: it deletes the icons")
	}
}

// elementAt returns the markup from the attribute given to the end of that tag, which is enough
// to assert about one control without depending on the shape of the rest of the page.
func elementAt(html, attr string) string {
	i := strings.Index(html, attr)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(html[:i], "<")
	rest := html[start:]
	if end := strings.Index(rest, "</button>"); end > 0 {
		return rest[:end+len("</button>")]
	}
	if end := strings.Index(rest, ">"); end > 0 {
		return rest[:end+1]
	}
	return rest
}

// GHOST-048. The table shows one row per proven node, and every column in it is something the
// published projection actually carries. Address and port are not among them by construction:
// the page exists to show that verification happened, not to republish somebody else's nodes in
// a second, more permanent form.
func TestNodeTableRendersOneRowPerNode(t *testing.T) {
	d := fixtureData(t)
	html := render(t, d, "ru", time.Now())
	if got := strings.Count(html, `<tr data-p=`); got != len(d.Nodes) {
		t.Fatalf("%d rows rendered, want %d", got, len(d.Nodes))
	}
	// The columns the reference has and this table cannot: asserted absent so restoring one is
	// a test failure rather than a quiet change of what the project publishes.
	for _, forbidden := range []string{"col_address", "col_port", "col_status"} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the table must not carry a %s column", forbidden)
		}
	}
	// The whole projection, spelled out. A field appearing here that NodeRow does not have
	// would mean the page started sourcing node detail from somewhere else.
	for _, want := range []string{">aa11bb22<", ">NL<", ">120<", ">12<"} {
		if !strings.Contains(html, want) {
			t.Errorf("the table is missing %s:\n%s", want, tableOf(html))
		}
	}
}

// The wl class is the one piece of per-node state that varies, and it is a word rather than a
// coloured swatch: colour alone is unreadable to a reader who cannot see it.
func TestMaskedClassIsMarkedAsText(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())
	tbl := tableOf(html)
	if n := strings.Count(tbl, `<i class="wl">WL</i>`); n != 1 {
		t.Fatalf("the wl mark appears %d times, want 1 (the fixture has one wl node):\n%s", n, tbl)
	}
	// The mark is explained on the page, not only in a test.
	if !strings.Contains(html, "WL —") && !strings.Contains(html, "WL &mdash;") {
		t.Error("the page must say what WL means")
	}
}

// INV-36. An absent measurement is not a slow one. A failed or skipped measurement rendered as
// zero states a number that was never taken.
func TestAbsentMeasurementIsNeverPrintedAsZero(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())
	tbl := tableOf(html)
	// The fixture's third node has no latency, no throughput and no streak.
	for _, zero := range []string{">0<", ">0.0<", `class="mbps">0`} {
		if strings.Contains(tbl, zero) {
			t.Errorf("an unmeasured value rendered as %s:\n%s", zero, tbl)
		}
	}
	// It is still a row, with the cells it does have.
	if !strings.Contains(tbl, ">ee55ff66<") {
		t.Errorf("the unmeasured node must still be listed:\n%s", tbl)
	}
}

// The table is ranked by evidence: longest streak first, then lowest latency. A node with no
// measured latency sorts last rather than first, because treating absent as zero would put the
// nodes we know least about at the top of a list whose whole claim is that it is ranked.
func TestNodeRowsAreRankedByEvidence(t *testing.T) {
	rows := buildRows(fixtureData(t).Nodes)
	got := []string{rows[0].ID, rows[1].ID, rows[2].ID}
	want := []string{"aa11bb22", "cc33dd44", "ee55ff66"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row order %v, want %v", got, want)
		}
	}
}

// A filter that cannot filter is worse than no filter: it makes the list look narrower than it
// is. So the tool row ships hidden and the script reveals it.
func TestFilterPanelArrivesHidden(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())
	tools := elementAt(html, `data-testid="node-tools"`)
	if !strings.Contains(tools, "hidden") {
		t.Fatalf("the tool row must arrive hidden:\n%s", tools)
	}
	if !strings.Contains(readAsset(t, "assets/site.js"), "tools.hidden = false") {
		t.Error("nothing reveals the tool row")
	}
	// A chip for a protocol with no proven nodes could only ever return nothing.
	if strings.Contains(html, `data-filter="hysteria2"`) {
		t.Error("a filter was offered for a protocol the corpus does not have")
	}
}

// tableOf returns the node table alone, so a row assertion does not depend on the rest of the
// page.
func tableOf(html string) string {
	i := strings.Index(html, `data-testid="node-rows"`)
	if i < 0 {
		return html
	}
	rest := html[i:]
	if end := strings.Index(rest, "</tbody>"); end > 0 {
		return rest[:end]
	}
	return rest
}

// One document, both languages. The control swaps an attribute instead of navigating, and the
// text of both languages is in the markup so the first paint is already correct without the
// script — which is the property that made client-side switching acceptable here at all.
func TestBothLanguagesLiveInOneDocument(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())
	for _, want := range []string{
		`<span lang="ru">Подписки</span>`,
		`<span lang="en">Subscriptions</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the document does not carry %s", want)
		}
	}
	if !strings.Contains(html, `data-lang="ru"`) {
		t.Error("the document does not declare which language it is showing")
	}
	// The hiding is CSS, not script: without this rule the page shows both languages at once.
	css := readAsset(t, "assets/site.css")
	for _, rule := range []string{`html[data-lang="ru"] [lang="en"]`, `html[data-lang="en"] [lang="ru"]`} {
		if !strings.Contains(css, rule) {
			t.Errorf("the stylesheet does not hide the other language: missing %s", rule)
		}
	}
}

// Switching still works with the script blocked, because each half of the control is a real link
// to a prerendered document. Both halves are links rather than one link and one span so that
// after a script-side switch either half is still operable from the keyboard.
func TestLanguageSwitchIsUsableWithoutScript(t *testing.T) {
	ru := render(t, fixtureData(t), "ru", time.Now())
	if !strings.Contains(ru, `href="en/" hreflang="en"`) {
		t.Errorf("the Russian page does not link to the English one:\n%s", elementAt(ru, `data-lang-to="en"`))
	}
	en := render(t, fixtureData(t), "en", time.Now())
	if !strings.Contains(en, `href="../" hreflang="ru"`) {
		t.Errorf("the English page does not link back:\n%s", elementAt(en, `data-lang-to="ru"`))
	}
	if !strings.Contains(en, `aria-current="page"`) {
		t.Error("the control does not mark the current language")
	}
}

// The fallback page sits one directory down, so every asset link has to climb. Getting this
// wrong is how a translated page ships unstyled — and it is now also how it ships without the
// illustration, which is the largest single asset on the page.
func TestAssetBaseClimbsForTheNestedPage(t *testing.T) {
	d := BuildSiteData(fixtureData(t), "https://example.test", time.Now())
	d.AssetBase = "../"
	var buf bytes.Buffer
	if err := RenderSite(&buf, d, "en"); err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{`href="../assets/site.css"`, `src="../assets/site.js"`, `src="../assets/hero.webp"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the nested page does not climb to its assets: missing %s", want)
		}
	}
}

// INV-44. A string key that does not exist must abort the render. The predecessor rewrote an
// unfilled token to a dash behind a safety net that existed because a visible one had shipped,
// so a missing label reached production looking like a design choice.
func TestUnknownStringKeyAbortsTheRender(t *testing.T) {
	funcs, err := siteFuncs("ru")
	if err != nil {
		t.Fatalf("building the function map: %v", err)
	}
	for _, body := range []string{`{{t "nope"}}`, `{{alt "nope"}}`, `{{template "s" (tt "nope")}}`} {
		tpl, perr := template.New("probe").Funcs(funcs).Parse(
			`{{define "s"}}{{range $l, $v := .}}{{$v}}{{end}}{{end}}` + body)
		if perr != nil {
			t.Fatalf("parsing %s: %v", body, perr)
		}
		if eerr := tpl.Execute(io.Discard, nil); eerr == nil {
			t.Errorf("%s rendered without error; a missing key must fail the render", body)
		}
	}
}

// Every key the templates ask for exists in both languages. This catches the typo at test time
// rather than at render time, and it is the gate that keeps a half-translated page impossible:
// a key added to one table and forgotten in the other fails here.
func TestEveryTemplateKeyExistsInBothLanguages(t *testing.T) {
	var sources strings.Builder
	err := fs.WalkDir(assets, "site", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, rerr := assets.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sources.Write(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the templates: %v", err)
	}

	re := regexp.MustCompile(`(^|[^A-Za-z_.])(tt|t|alt) "([a-z0-9_]+)"`)
	found := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(sources.String(), -1) {
		found[m[3]] = true
	}
	if len(found) < 20 {
		t.Fatalf("only %d keys found in the templates; the scan is not finding them", len(found))
	}
	for key := range found {
		for _, lang := range Languages {
			if _, ok := translations[lang][key]; !ok {
				t.Errorf("template key %q is missing from the %s table", key, lang)
			}
		}
	}
}

// --- the catalogue mix, and what the page is allowed to spend space on ----------------

// manyCountries is a corpus wider than the mix band's cap, so the truncation is exercised.
func manyCountries(t *testing.T) Data {
	t.Helper()
	d := fixtureData(t)
	ccs := []string{"NL", "DE", "US", "FI", "SE", "FR", "GB", "JP", "SG", "CA", "PL", "TR"}
	rows := make([]NodeRow, 0, 78)
	id := 0
	for i, cc := range ccs {
		// Descending counts, so the order the band renders is unambiguous.
		for k := 0; k <= len(ccs)-i; k++ {
			id++
			rows = append(rows, NodeRow{
				ID: fmt.Sprintf("%08x", id), CC: cc, Protocol: "vless", Transport: "tcp",
				Class: "open", LatencyMS: 100 + id, Streak: 2, VerifiedAt: d.GeneratedAt,
			})
		}
	}
	d.Nodes = rows
	return d
}

// The band's heading counts the corpus, not its own bars.
//
// The band plots the largest eight, so a heading that counted what it had drawn would report
// eight countries in a catalogue that has twelve — a figure that is wrong in the direction that
// flatters, produced by the page rather than by a run. It is the same defect as the
// predecessor's "UN" country: a value invented at the display layer and then believed.
func TestMixHeadingCountsTheCorpusAndNotItsOwnBars(t *testing.T) {
	d := manyCountries(t)
	site := BuildSiteData(d, "https://example.github.io/ShellShift", d.GeneratedAt)

	var countries *MixBand
	for i := range site.Mix {
		if site.Mix[i].Key == "countries" {
			countries = &site.Mix[i]
		}
	}
	if countries == nil {
		t.Fatal("no countries band was built")
	}
	if len(countries.Rows) != 8 {
		t.Errorf("the band plots %d rows, want the cap of 8", len(countries.Rows))
	}
	if countries.Total != 12 {
		t.Errorf("the band reports %d distinct countries, want the corpus's 12", countries.Total)
	}

	// And the heading says both, so a reader can see the band is a summary. "8/12", in the same
	// idiom the node tally uses two bands below.
	html := render(t, d, "ru", d.GeneratedAt)
	if !strings.Contains(html, ">8/12<") {
		t.Errorf("a truncated band must state what it left out:\n%s", elementAt(html, `data-testid="country-bars"`))
	}
}

// Protocols are a bar band, not a second table. The section that used to be headed "Протоколы"
// was the whole node inventory: 695 rows of seven columns, 35 627 px of a 38 541 px document.
func TestProtocolsAreABandBesideCountries(t *testing.T) {
	html := render(t, manyCountries(t), "ru", time.Now())
	for _, want := range []string{`data-testid="protocol-bars"`, `data-testid="country-bars"`} {
		if !strings.Contains(html, want) {
			t.Errorf("the catalogue mix is missing %s", want)
		}
	}
	// One mark for both bands. Two bar implementations is how the same rule ends up rendered
	// twice and disagreeing, which is the failure the whole invariants file is about.
	if n := strings.Count(html, `class="bar-track"`); n != 9 {
		t.Errorf("%d bars rendered, want 1 protocol + 8 countries", n)
	}
}

// The proof comes before the thing it justifies, and the inventory comes last.
//
// The funnel used to be rendered after the node table, which put the signature element and the
// one number the project is about at y=37 589 of a 38 541 px document: a visitor reached it only
// by scrolling past 695 table rows, so in practice nobody reached it at all.
func TestTheFunnelIsRenderedBeforeTheInventory(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())
	funnel := strings.Index(html, `data-testid="funnel"`)
	table := strings.Index(html, `data-testid="node-rows"`)
	if funnel < 0 || table < 0 {
		t.Fatalf("funnel at %d, table at %d; both must be on the page", funnel, table)
	}
	if funnel > table {
		t.Error("the funnel is rendered after the node table, where the predecessor's dashboard put it")
	}
}

// The node table is bounded, so no band's height is a function of the size of the corpus.
//
// Not a byte budget — TestNodeRowStaysCheap holds that — but a layout one: at 695 proven nodes
// the unbounded table was 92% of the document and it pushed every band after it out of reach.
func TestTheNodeTableIsHeldToABoundedPane(t *testing.T) {
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	pane := css[strings.Index(css, ".tablewrap {"):]
	pane = pane[:strings.Index(pane, "}")]
	if !strings.Contains(pane, "max-height") {
		t.Errorf("the table pane has no ceiling, so the section grows with the corpus:\n%s", pane)
	}
	// A scrolled pane whose column names have left the top is a grid of unlabelled values.
	if !strings.Contains(css, "position: sticky") {
		t.Error("the table header does not stick, so a scrolled pane loses its column names")
	}
}

// Exactly one figure at display size, and the hero band is not where it is.
//
// The band carried four stat tiles — proven, countries, protocols, yield — and every figure in
// them was published a second time further down: proven and yield are the funnel's last row,
// countries and protocols are the length of a band in the catalogue mix. A number rendered in
// two places is a number that can disagree with itself, and the house style allows one figure at
// display scale per view. Asserted absent so a revert is a failure rather than a quiet
// duplication.
func TestOneDisplayFigureAndTheHeroRestatesNothing(t *testing.T) {
	d := fixtureData(t)
	html := render(t, d, "ru", time.Now())

	if n := strings.Count(html, `class="num big"`); n != 1 {
		t.Errorf("%d figures at display size, want exactly 1 (the survivors)", n)
	}

	hero := html[strings.Index(html, `class="hero" data-testid="hero"`):]
	hero = hero[:strings.Index(hero, "</section>")]
	// 693 is the funnel's last row and 4.8 is its yield. Neither belongs in the band as well.
	for _, restated := range []string{"693", "4.8"} {
		if strings.Contains(hero, restated) {
			t.Errorf("the hero band restates %q, which the funnel already publishes", restated)
		}
	}
	if strings.Contains(html, `data-stat=`) {
		t.Error("the stat-tile row is back in the hero band")
	}
}

// The copy control and the field it falls back to are in the same card, and the script looks the
// field up from the card.
//
// The control moved from under the field into the card's head row, which left it with a parent
// that holds no field at all. The clipboard fallback is selecting that field — the predecessor
// opened a window.prompt instead, which is a dialog and not an affordance — so a lookup that
// silently returns nothing removes the fallback while every test about the button still passes.
func TestTheCopyFallbackFindsItsFieldFromTheCard(t *testing.T) {
	html := render(t, fixtureData(t), "ru", time.Now())
	card := html[strings.Index(html, `data-testid="endpoint-card"`):]
	card = card[:strings.Index(card, "</li>")]
	for _, want := range []string{`data-testid="endpoint-copy"`, `data-testid="endpoint-url"`} {
		if !strings.Contains(card, want) {
			t.Fatalf("the card is missing %s:\n%s", want, card)
		}
	}

	js := readAsset(t, "assets/site.js")
	if !strings.Contains(js, `btn.closest("[data-testid=endpoint-card]")`) {
		t.Error("the field is not looked up from the card, so the clipboard fallback selects nothing")
	}
	if strings.Contains(js, "btn.parentElement.querySelector") {
		t.Error("the field is looked up from the button's parent, which no longer contains it")
	}
}
