package publish

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The palette is the reference mockup's, and the reference mockup is very low contrast: it is
// lavender-grey text on lavender-grey ground, and every value in it was measured off a PNG
// rather than designed. Reading it off and shipping it is exactly how a page ends up looking
// right in a screenshot and being unreadable on a laptop in daylight.
//
// So the tokens are computed and this file is the receipt. It is deliberately arithmetic and not
// judgement: nothing here is a matter of taste, and a token nudged for looks that drops below
// its floor fails.

// contrastFloors is what each token is used for, which is what decides its floor. Text at body
// size needs 4.5:1; a mark that is not text needs 3:1, and the three status colours are held to
// the text floor anyway because they are also used as a border and beside a label.
var contrastFloors = map[string]float64{
	"ink": 4.5, "ink-2": 4.5, "ink-3": 4.5,
	"accent": 4.5, "ok": 4.5, "warn": 4.5, "bad": 4.5,
	"hairline-strong": 1.8,
}

func TestPaletteClearsItsContrastFloors(t *testing.T) {
	for _, theme := range []string{"light", "dark"} {
		tokens := themeTokens(t, theme)
		surface := tokens["surface"]
		if surface == "" {
			t.Fatalf("%s theme declares no surface", theme)
		}
		for name, floor := range contrastFloors {
			hex := tokens[name]
			if hex == "" {
				t.Errorf("%s theme declares no --%s", theme, name)
				continue
			}
			if got := contrastRatio(t, hex, surface); got < floor {
				t.Errorf("%s: --%s %s on %s is %.2f:1, below the %.1f:1 floor",
					theme, name, hex, surface, got, floor)
			}
		}
	}
}

// A dark surface needs its marks inside a lightness band: too light and they glare, too dark and
// they vanish. This is the check that found the previous dark theme — #4FD6E0, #2FD98A, #F5B02E
// and #FF7A75 all sat at OKLCH L 0.73 to 0.81, above a band that ends at 0.67, because the dark
// theme had been produced by flipping the light one rather than by being chosen.
func TestColouredTokensSitInTheirLightnessBand(t *testing.T) {
	bands := map[string][2]float64{"light": {0.43, 0.77}, "dark": {0.48, 0.67}}
	for theme, band := range bands {
		tokens := themeTokens(t, theme)
		for _, name := range []string{"accent", "ok", "warn", "bad"} {
			l, c := oklchLC(t, tokens[name])
			if l < band[0] || l > band[1] {
				t.Errorf("%s: --%s %s is at OKLCH L %.3f, outside %.2f–%.2f",
					theme, name, tokens[name], l, band[0], band[1])
			}
			// Below the chroma floor a hue reads as grey, and a mark that reads as grey is
			// not carrying the state it was given the colour for.
			if c < 0.10 {
				t.Errorf("%s: --%s %s has chroma %.3f, below the 0.10 floor",
					theme, name, tokens[name], c)
			}
		}
	}
}

// The hero band puts light ink over the illustration, and the only thing between them is the
// scrim. This measures the arrangement that actually ships: it reads the veil the gradient
// reaches at the copy column's right edge, composites the band's surface over the worst pixel
// the art can put there, and requires the text floor.
//
// It used to assert a hardcoded minAlphaUnderCopy of 0.42 instead. That number was not a
// property of the design, it was a property of one illustration: the previous art had a pale fog
// on its left half whose brightest decile was #7A7B95, and 42% was the veil that particular
// backdrop needed. Held as a floor it then forbade lightening the wash when the art was replaced
// by a much darker one — a gate enforcing a retired asset's requirement against the current
// asset's design. So the alpha is read, not asserted, and only the contrast is a floor.
//
// worstBackdrop is measured, not assumed: it is the brightest decile of the left half of
// assets/hero.webp. When the illustration is replaced it has to be measured again, and this test
// is the thing that will notice.
//
// It is deliberately conservative in two ways. The art under the copy column is at most partly
// opaque there — hero-art is masked in from its own left edge — and the leftmost part of the copy
// column has no art beneath it at all. Both make the real backdrop darker than the one computed
// here.
func TestHeroInkClearsTheScrimmedArt(t *testing.T) {
	// Measured off assets/hero.webp: the 90th-percentile luminance of the left half.
	const worstBackdrop = "#262833"
	// Where the copy column ends, as a fraction of the band: grid-template-columns is
	// minmax(0, 33rem) inside a 62rem wrap, so 33/62.
	const copyColumnEdge = 33.0 / 62.0

	css := readAsset(t, "assets/site.css")
	stops := scrimStops(t, css)
	if len(stops) < 3 {
		t.Fatalf("found %d scrim stops, expected the desktop gradient's stops", len(stops))
	}
	// The ramp has to descend for "the veil at the copy edge" to be the worst veil the copy
	// sits under. A non-monotonic gradient would make this test measure the wrong stop.
	for i := 1; i < len(stops); i++ {
		if stops[i].alpha > stops[i-1].alpha || stops[i].pos <= stops[i-1].pos {
			t.Fatalf("the scrim is not a descending ramp at stop %d (%.2f at %.0f%%)",
				i, stops[i].alpha, stops[i].pos*100)
		}
	}

	alpha := scrimAlphaAt(stops, copyColumnEdge)
	tokens := themeTokens(t, "light")
	backdrop := composite(t, tokens["h-surface"], alpha, worstBackdrop)
	for _, name := range []string{"h-ink", "h-ink-2"} {
		got := contrastRatio(t, tokens[name], backdrop)
		if got < 4.5 {
			t.Errorf("--%s %s over the scrim at the copy edge (%.2f alpha, backdrop %s) "+
				"is %.2f:1, below 4.5:1", name, tokens[name], alpha, backdrop, got)
		}
		t.Logf("--%s over %s at alpha %.2f: %.2f:1", name, backdrop, alpha, got)
	}
}

// --- the arithmetic ------------------------------------------------------------
//
// Written out here rather than pulled in, because a colour-space dependency for forty lines of
// well-specified formulae is a supply-chain surface this project does not need, and because the
// values these produce are checked against an external validator in the design document.

var tokenRe = regexp.MustCompile(`--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})`)

// themeTokens reads one theme's declarations straight out of the shipped stylesheet, so the test
// cannot pass against a table that the page does not use.
func themeTokens(t *testing.T, theme string) map[string]string {
	t.Helper()
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	selector := ":root {"
	if theme == "dark" {
		selector = `:root[data-theme="dark"] {`
	}
	i := strings.Index(css, selector)
	if i < 0 {
		t.Fatalf("no %s block in the stylesheet", selector)
	}
	block := css[i+len(selector):]
	if end := strings.Index(block, "}"); end > 0 {
		block = block[:end]
	}
	out := map[string]string{}
	for _, m := range tokenRe.FindAllStringSubmatch(block, -1) {
		out[m[1]] = strings.ToUpper(m[2])
	}
	// The dark block overrides the light one, so anything it does not restate is inherited.
	if theme == "dark" {
		for k, v := range themeTokensLight(t, css) {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}

func themeTokensLight(t *testing.T, css string) map[string]string {
	t.Helper()
	i := strings.Index(css, ":root {")
	block := css[i+len(":root {"):]
	if end := strings.Index(block, "}"); end > 0 {
		block = block[:end]
	}
	out := map[string]string{}
	for _, m := range tokenRe.FindAllStringSubmatch(block, -1) {
		out[m[1]] = strings.ToUpper(m[2])
	}
	return out
}

// Alpha and position together: the position is what makes "the veil under the copy"
// a measurable quantity instead of a stop index somebody has to keep in step by hand.
var scrimRe = regexp.MustCompile(`rgba\(16,\s*19,\s*28,\s*([0-9.]+)\)\s+([0-9.]+)%`)

// The narrow band puts the same light ink over the whole illustration, not over its dark left
// half, and until the scrim was lightened for a darker asset nothing checked that case at all.
//
// It is the harder one: at this width the art covers the band, the mask comes off, and the copy
// sits directly over the subject's lit face — the brightest thing in the picture. So the backdrop
// here is measured over the region the phone actually shows beneath the copy, and the floor is
// the thinnest the vertical ramp ever gets.
func TestHeroInkClearsTheArtOnANarrowBand(t *testing.T) {
	// Measured off assets/hero.webp: 90th-percentile luminance of the full width, source y
	// 3.7%–62%, which is the window `object-position: 62% 14%` puts under the copy.
	const worstBackdrop = "#6E665E"

	css := readAsset(t, "assets/site.css")
	i := strings.Index(css, "@media (max-width: 700px)")
	if i < 0 {
		t.Fatal("no narrow breakpoint: the phone band has its own scrim")
	}
	stops := scrimStops(t, css[i:])
	if len(stops) < 2 {
		t.Fatalf("found %d stops in the narrow scrim, expected the vertical ramp's", len(stops))
	}

	thinnest := stops[0].alpha
	for _, st := range stops {
		if st.alpha < thinnest {
			thinnest = st.alpha
		}
	}
	tokens := themeTokens(t, "light")
	backdrop := composite(t, tokens["h-surface"], thinnest, worstBackdrop)
	for _, name := range []string{"h-ink", "h-ink-2"} {
		got := contrastRatio(t, tokens[name], backdrop)
		if got < 4.5 {
			t.Errorf("--%s %s over the narrow scrim at its thinnest (%.2f alpha, backdrop %s) "+
				"is %.2f:1, below 4.5:1", name, tokens[name], thinnest, backdrop, got)
		}
		t.Logf("--%s over %s at alpha %.2f: %.2f:1", name, backdrop, thinnest, got)
	}
}

// scrimStop is one colour stop of the hero gradient: how opaque the veil is, and where.
type scrimStop struct {
	alpha float64
	pos   float64 // fraction of the band, 0..1
}

// scrimStops reads the desktop scrim out of the shipped stylesheet, so the test cannot pass
// against a gradient the page does not use.
func scrimStops(t *testing.T, css string) []scrimStop {
	t.Helper()
	i := strings.Index(css, ".hero::after")
	if i < 0 {
		t.Fatal("no .hero::after rule: the scrim is what makes the hero copy readable")
	}
	block := css[i:]
	if end := strings.Index(block, "}"); end > 0 {
		block = block[:end]
	}
	var out []scrimStop
	for _, m := range scrimRe.FindAllStringSubmatch(block, -1) {
		a, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			t.Fatalf("unreadable scrim alpha %q", m[1])
		}
		p, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			t.Fatalf("unreadable scrim position %q", m[2])
		}
		out = append(out, scrimStop{alpha: a, pos: p / 100})
	}
	return out
}

// scrimAlphaAt interpolates the veil at one position across the band, which is what a browser
// paints between two stops.
func scrimAlphaAt(stops []scrimStop, at float64) float64 {
	if at <= stops[0].pos {
		return stops[0].alpha
	}
	for i := 1; i < len(stops); i++ {
		if at <= stops[i].pos {
			prev, cur := stops[i-1], stops[i]
			f := (at - prev.pos) / (cur.pos - prev.pos)
			return prev.alpha + f*(cur.alpha-prev.alpha)
		}
	}
	return stops[len(stops)-1].alpha
}

func parseHex(t *testing.T, hex string) [3]float64 {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("not a hex colour: %q", hex)
	}
	var out [3]float64
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(hex[1+i*2:3+i*2], 16, 8)
		if err != nil {
			t.Fatalf("unreadable hex %q", hex)
		}
		out[i] = float64(v) / 255
	}
	return out
}

// composite lays fg at alpha over bg and returns the result, which is what the eye actually
// reads through the scrim.
func composite(t *testing.T, fg string, alpha float64, bg string) string {
	t.Helper()
	f, b := parseHex(t, fg), parseHex(t, bg)
	var out [3]int
	for i := 0; i < 3; i++ {
		out[i] = int(math.Round((f[i]*alpha + b[i]*(1-alpha)) * 255))
	}
	return fmt.Sprintf("#%02X%02X%02X", out[0], out[1], out[2])
}

func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	c := parseHex(t, hex)
	lin := func(v float64) float64 {
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c[0]) + 0.7152*lin(c[1]) + 0.0722*lin(c[2])
}

func contrastRatio(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := relLuminance(t, a), relLuminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// oklchLC returns a colour's OKLCH lightness and chroma. Björn Ottosson's OKLab, verbatim.
func oklchLC(t *testing.T, hex string) (float64, float64) {
	t.Helper()
	c := parseHex(t, hex)
	lin := func(v float64) float64 {
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	r, g, b := lin(c[0]), lin(c[1]), lin(c[2])
	l := math.Cbrt(0.4122214708*r + 0.5363325363*g + 0.0514459929*b)
	m := math.Cbrt(0.2119034982*r + 0.6806995451*g + 0.1073969566*b)
	s := math.Cbrt(0.0883024619*r + 0.2817188376*g + 0.6299787005*b)
	L := 0.2104542553*l + 0.7936177850*m - 0.0040720468*s
	A := 1.9779984951*l - 2.4285922050*m + 0.4505937099*s
	B := 0.0259040371*l + 0.7827717662*m - 0.8086757660*s
	return L, math.Hypot(A, B)
}

// A pseudo-element that covers its host — the hero band's scrim — paints on every element
// carrying its class, not just the one it was written for. The hero figure in the funnel used to
// be `class="num hero"`, and `.hero::after` matched it: a dark gradient rectangle appeared across
// the one number the whole project is about, and no string assertion could see it.
//
// So every class whose ::after covers its host must belong to exactly one element on the page.
func TestCoveringPseudoElementClassesAreNotShared(t *testing.T) {
	css := stripCSSComments(readAsset(t, "assets/site.css"))
	re := regexp.MustCompile(`\.([a-z][a-z0-9-]*)::after\s*\{[^}]*inset:\s*0`)
	matches := re.FindAllStringSubmatch(css, -1)
	if len(matches) == 0 {
		t.Skip("no covering pseudo-element in the stylesheet")
	}
	html := render(t, fixtureData(t), "ru", time.Now())
	for _, m := range matches {
		class := m[1]
		if n := countClassUses(html, class); n != 1 {
			t.Errorf("class %q carries a covering ::after and appears on %d elements; "+
				"the scrim will paint over all of them", class, n)
		}
	}
}

// countClassUses counts elements whose class attribute contains name as a whole word.
func countClassUses(html, name string) int {
	re := regexp.MustCompile(`class="([^"]*)"`)
	n := 0
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		for _, c := range strings.Fields(m[1]) {
			if c == name {
				n++
			}
		}
	}
	return n
}
