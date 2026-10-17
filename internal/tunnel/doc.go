// Package tunnel owns the only interface through which traffic is dialed.
//
// The primary implementation constructs one sing-box outbound per node in-process
// and exposes its DialContext, so a malformed node can fail only itself. The
// predecessor ran a sing-box subprocess per batch of fifty, where a single rejected
// outbound prevented the process from binding and killed all fifty — see INV-00.
//
// Because sing-box's Go API carries no compatibility guarantee across minor
// versions, every use of it is confined behind Dialer. A subprocess-backed
// implementation is kept as both a fallback and a conformance oracle: the two must
// return identical verdicts for the same fixtures.
package tunnel
