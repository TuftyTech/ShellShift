// Package decode turns an untrusted proxy URI into a validated model.Node.
//
// This is where the most expensive knowledge in the project lives. Every guard in
// here closes a production failure of the predecessor, named by its INV number, and every
// guard has a table test that names its INV number. Read INV-01 through INV-29
// before changing anything.
//
// Decoding is tolerant of malformed input but never silent: each repair
// (base64 padding, URL-safe alphabet, HTML unescaping) increments a counter so that
// "the source served garbage" is distinguishable from "we failed to parse it".
// A node that cannot be decoded is rejected, never coerced into a default — INV-29.
package decode
