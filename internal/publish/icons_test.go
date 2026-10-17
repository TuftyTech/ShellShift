package publish

import (
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// INV-44. A template that cannot render must fail, not degrade. An icon name that does not
// exist is the same class of fault as an unfilled token: returning an empty string would put a
// button with nothing in it on the page and keep the build green.
func TestUnknownIconIsAnError(t *testing.T) {
	if _, err := icon("no_such_icon", ""); err == nil {
		t.Fatal("an unknown icon name must be an error")
	}
	got, err := icon("contrast", "i")
	if err != nil {
		t.Fatalf("contrast: %v", err)
	}
	for _, want := range []string{`class="i"`, `viewBox="0 -960 960 960"`, `aria-hidden="true"`,
		`focusable="false"`, "<path d="} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("rendered icon is missing %s: %s", want, got)
		}
	}
	// An empty class omits the attribute rather than emitting class="".
	bare, err := icon("check", "")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Contains(string(bare), "class=") {
		t.Fatalf("an empty class must omit the attribute: %s", bare)
	}
}

// The table is spliced into HTML through template.HTML, which is an escaping bypass. That is
// only safe while every byte in it is path data, so the alphabet is asserted rather than
// assumed: one quote in this table would be an injection point in the one place the renderer
// does not escape.
func TestIconPathDataIsPathDataOnly(t *testing.T) {
	const allowed = "MmLlHhVvCcSsQqTtAaZz0123456789.- ,"
	for name, d := range icons {
		if d == "" {
			t.Errorf("%s: empty path", name)
			continue
		}
		for _, r := range d {
			if !strings.ContainsRune(allowed, r) {
				t.Errorf("%s: %q is not path data", name, r)
				break
			}
		}
	}
}

// A set with an entry nothing renders is dead scaffolding, and dead scaffolding is how the
// predecessor shipped a theme switcher wired to nothing. The gate is the reason the set can
// stay small.
//
// Two places count as rendering: a template naming the icon as a literal, and package code
// naming it as a string, so an icon chosen by Go rather than written into a template still
// counts. Nothing does the latter now — the hero band's four stat tiles did, and they are gone
// along with the four figures they duplicated — but the branch stays, because the alternative is
// a gate that fires on a correct change. icons.go itself and the tests are excluded on purpose:
// counting the map that declares the icon, or a test that merely mentions it, would make the
// gate unable to fail.
func TestEveryIconIsRenderedBySomeTemplate(t *testing.T) {
	var sources strings.Builder
	err := fs.WalkDir(assets, "site", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		sources.Write(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the templates: %v", err)
	}
	templates := sources.String()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var code strings.Builder
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "icons.go" {
			continue
		}
		b, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("reading %s: %v", name, rerr)
		}
		code.Write(b)
	}

	for name := range icons {
		if strings.Contains(templates, `icon "`+name+`"`) {
			continue
		}
		if strings.Contains(code.String(), `"`+name+`"`) {
			continue
		}
		t.Errorf("icon %q is in the set but nothing renders it", name)
	}
}

// The house style declares one sans-serif family and one monospace family, downloads no font and
// reaches no third-party origin. That is not only a byte saving: the page carries
// `default-src 'self'`, so a font or a sprite from a CDN would silently fail to load.
func TestStylesheetShipsNoWebFontAndNoThirdPartyOrigin(t *testing.T) {
	css := readAsset(t, "assets/site.css")
	// Comments are removed first: this file names the reference site it follows, and a gate that
	// fires on a URL in a comment would be answered by deleting the comment.
	rules := stripCSSComments(css)

	for _, forbidden := range []string{"@font-face", "@import", "http://", "https://", "//fonts."} {
		if strings.Contains(rules, forbidden) {
			t.Errorf("the stylesheet must not contain %q outside a comment", forbidden)
		}
	}
	if n := strings.Count(rules, "font-family"); n != 2 {
		t.Errorf("font-family is declared %d times, want 2 (one sans, one monospace)", n)
	}
	if !strings.Contains(rules, "font-family: system-ui, sans-serif;") {
		t.Error("the sans-serif family must be the reference's system-ui, sans-serif")
	}
	// The reference calls +0.11em the measured ceiling for letter-spacing. Exceeding it is what
	// turns a micro-label into a decoration, so the ceiling is a gate and not a note.
	for _, spacing := range letterSpacings(rules) {
		if spacing > 0.11 {
			t.Errorf("letter-spacing %gem exceeds the 0.11em ceiling", spacing)
		}
	}
}

// The chrome has a budget, and the chrome is what the page costs before it says anything about
// any node: the stylesheet, the script, and the document rendered with an empty catalogue.
//
// It used to be one number over the whole page, which stopped working the day the page grew a
// table: a ceiling that rises with the size of the corpus defends nothing. So the budget is
// three gates — this one, TestNodeRowStaysCheap for the part that scales, and
// TestRasterAssetsFitTheirBudget for the illustration — and each of them can fail on its own.
func TestSiteChromeFitsItsBudget(t *testing.T) {
	// 96 KiB, raised from 80 when the node card landed. The card's client is about 10 KiB of
	// script: the payload fetch, the field renderer, the mask, the clipboard and the dialog. It is
	// chrome by the definition this gate uses — its size is set by the field list, not by the
	// corpus — and the alternative was rendering a card per row, which for 1782 nodes is about
	// 1.8 MB of markup and every credential in an indexable page.
	//
	// What this gate does not see, stated rather than left to be discovered: the card's own markup
	// lives inside `{{if .Rows}}`, so an empty catalogue renders none of it. Its cost is the four
	// section headings and the field labels in both languages, bounded by detailSections() and by
	// nothing else.
	//
	// 80 KiB, raised from 60 when the legal notice landed. The notice is nine statements with a
	// heading and a body each, rendered in both languages into the same document like every
	// other string on this page, which is about 7 KiB of the increase; the rest is the
	// stylesheet and the script it needs. It is text a reader consults, not markup that scales
	// with the corpus, so it belongs under this gate rather than exempted from it — and the
	// gate's job is to catch the chrome growing by accident, which is why the ceiling moves
	// deliberately and with the reason written down instead of being deleted.
	//
	// Uncompressed, and the wire cost is far lower: the document carries each string twice, once
	// per language, which is close to ideal input for the transfer encoding Pages applies.
	const budget = 96 * 1024

	total := len(render(t, emptyCatalogue(t), "ru", time.Now()))
	for _, name := range AssetNames() {
		if isRaster(name) {
			continue
		}
		total += len(readAsset(t, name))
	}
	if total > budget {
		t.Errorf("the chrome is %d bytes, over the %d-byte budget", total, budget)
	}
	t.Logf("chrome: %d bytes of %d", total, budget)
}

// The node row is the only markup on this page multiplied by the size of the corpus, so it gets
// its own ceiling — and one that does not move when the corpus does. Measured as the difference
// between rendering a hundred and one rows, which is the marginal cost and nothing else.
func TestNodeRowStaysCheap(t *testing.T) {
	const ceiling = 220

	one := len(render(t, withNodes(t, 1), "ru", time.Now()))
	many := len(render(t, withNodes(t, 101), "ru", time.Now()))
	perRow := (many - one) / 100
	if perRow > ceiling {
		t.Errorf("a node row costs %d bytes, over the %d-byte ceiling", perRow, ceiling)
	}
	t.Logf("node row: %d bytes of %d", perRow, ceiling)
}

// The illustration is the first raster asset this project has ever shipped, and it is held to
// its own number rather than folded into the chrome: one is a fixed cost paid once by a cached
// image, the other is on the critical path of every render.
func TestRasterAssetsFitTheirBudget(t *testing.T) {
	const budget = 120 * 1024

	total := 0
	for _, name := range RasterAssets() {
		total += len(readAsset(t, name))
	}
	if total > budget {
		t.Errorf("the raster assets are %d bytes, over the %d-byte budget", total, budget)
	}
	t.Logf("raster: %d bytes of %d", total, budget)
}

func isRaster(name string) bool {
	for _, r := range RasterAssets() {
		if r == name {
			return true
		}
	}
	return false
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := Asset(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

// letterSpacings pulls every `letter-spacing: <n>em` value out of a stylesheet. Declarations in
// any other unit are not used by this file and would need their own reading.
func letterSpacings(css string) []float64 {
	var out []float64
	for _, chunk := range strings.Split(css, "letter-spacing:")[1:] {
		value := strings.TrimSpace(chunk)
		end := strings.IndexAny(value, ";}")
		if end < 0 {
			continue
		}
		value = strings.TrimSuffix(strings.TrimSpace(value[:end]), "em")
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		out = append(out, f)
	}
	return out
}

// stripCSSComments removes /* ... */ blocks so a rule check cannot be satisfied by a comment or
// tripped by one.
func stripCSSComments(css string) string {
	var b strings.Builder
	for {
		i := strings.Index(css, "/*")
		if i < 0 {
			b.WriteString(css)
			return b.String()
		}
		b.WriteString(css[:i])
		rest := css[i+2:]
		j := strings.Index(rest, "*/")
		if j < 0 {
			return b.String()
		}
		css = rest[j+2:]
	}
}
