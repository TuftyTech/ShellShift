package publish

import (
	"fmt"
	"html/template"
)

// icons is the whole icon set: Material Symbols, outlined, 24 px, fill 0.
//
// The path data is verbatim from Google's material-design-icons, in the same family and style
// the reference site uses. That was established rather than assumed: its `contrast` and
// `description` paths were compared byte-for-byte against
// symbols/web/<name>/materialsymbolsoutlined/<name>_24px.svg first, because the rounded and
// sharp cuts of the same icon are different path data, and mixing two cuts is how a set stops
// looking like a set.
//
// Inline paths rather than a font or a sprite. The policy on this page is `default-src 'self'`
// with no third-party origin permitted at all, so an icon font from a CDN would not load —
// and the reference downloads no font either. An inline path also cannot 404, costs no
// request, and takes its colour from CSS, so it follows the theme with no second asset.
var icons = map[string]string{
	// The theme control, and the same icon the reference site uses for the same control.
	"contrast": "M480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 " +
		"127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 " +
		"54-127 85.5T480-80Zm40-83q119-15 199.5-104.5T800-480q0-123-80.5-212.5T520-797v634Z",

	// The copy control, and the state it enters once the clipboard has the URL.
	"content_copy": "M360-240q-33 0-56.5-23.5T280-320v-480q0-33 23.5-56.5T360-880h360q33 0 56.5 " +
		"23.5T800-800v480q0 33-23.5 56.5T720-240H360Zm0-80h360v-480H360v480ZM200-80q-33 " +
		"0-56.5-23.5T120-160v-560h80v560h440v80H200Zm160-240v-480 480Z",
	"check": "M382-240 154-468l57-57 171 171 367-367 57 57-424 424Z",

	// The advisory block. The panel says the project runs no servers, which is the one thing on
	// the page a visitor is most likely to assume the opposite of.
	"info": "M440-280h80v-240h-80v240Zm40-320q17 0 28.5-11.5T520-640q0-17-11.5-28.5T480-680q-17 " +
		"0-28.5 11.5T440-640q0 17 11.5 28.5T480-600Zm0 520q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 " +
		"31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 " +
		"83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 " +
		"0-227 93t-93 227q0 134 93 227t227 93Zm0-320Z",

	// The node table's search field, and the one link on the page that leaves this origin.
	"search": "M784-120 532-372q-30 24-69 38t-83 14q-109 0-184.5-75.5T120-580q0-109 75.5-184.5T380-840q109 0 184.5 75.5T640-580q0 44-14 83t-38 69l252 252-56 56Z" +
		"M380-400q75 0 127.5-52.5T560-580q0-75-52.5-127.5T380-760q-75 0-127.5 52.5T200-580q0 75 52.5 127.5T380-400Z",
	// The node card's close button. A dialog needs a visible way out beside Esc and the backdrop,
	// because neither is discoverable and one of them is not available on a touch screen.
	"close": "M256-200l-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 " +
		"56-224-224-224 224Z",
	"open_in_new": "M200-120q-33 0-56.5-23.5T120-200v-560q0-33 23.5-56.5T200-840h280v80H200v560h560v-280h80v280q0 33-23.5 56.5T760-120H200Z" +
		"m188-212-56-56 372-372H560v-80h280v280h-80v-144L388-332Z",
}

// icon renders one icon from the set. An empty class omits the attribute.
//
// An unknown name is an error, and in html/template an error from a function aborts the whole
// render. Returning an empty string instead would put a button with nothing in it on the page
// and keep the build green, which is the shape of the predecessor's failure the render gate
// exists for (INV-44).
//
// The result is template.HTML, which is an escaping bypass, and it is confined to this one
// function for that reason: every byte it emits comes from the constant table above or from a
// class name written in a template. No value from a run, a feed or a node reaches it.
func icon(name, class string) (template.HTML, error) {
	d, ok := icons[name]
	if !ok {
		return "", fmt.Errorf("publish: no icon %q", name)
	}
	var attr string
	if class != "" {
		attr = fmt.Sprintf(" class=%q", class)
	}
	// aria-hidden, and every control carrying an icon also carries text or an aria-label: an
	// icon is never the accessible name. focusable="false" stops legacy engines from making the
	// SVG its own tab stop, which puts an unlabelled stop in the middle of the header.
	return template.HTML(fmt.Sprintf(
		`<svg%s viewBox="0 -960 960 960" aria-hidden="true" focusable="false"><path d=%q/></svg>`,
		attr, d)), nil
}
