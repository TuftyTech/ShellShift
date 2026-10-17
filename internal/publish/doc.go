// Package publish renders the subscription bundles, the data file consumed by the
// dashboard, and the static site.
//
// Two safety rules are non-negotiable and both are covered by tests that exist from
// day one:
//
//   - An empty or implausible result never replaces a previously published bundle
//     (INV-43). The predecessor truncated every subscription file unconditionally.
//   - A template that fails to render fails the build. It never silently republishes
//     the previous output, and an unfilled placeholder is an error rather than a
//     substituted dash (INV-44).
//
// Rendering uses html/template, whose contextual autoescaping is the reason node
// data cannot break out of an attribute.
package publish
