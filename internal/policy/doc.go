// Package policy is the Zero-Trust boundary. Nothing reaches the dialer without
// passing through here.
//
// Responsibilities:
//   - schema-first field validation against explicit allowlists (never blocklists)
//   - the egress guard: resolve once, vet the resolved address, dial that pinned
//     address. Denies loopback, 0.0.0.0/8, RFC1918, 100.64/10, 169.254/16 including
//     the cloud metadata address, multicast, reserved, and the IPv6 equivalents —
//     for every protocol and transport, with no exemptions (INV-33)
//   - whitelist classification, including proof that Reality masking is real rather
//     than merely that the domain appears in a list (INV-32)
package policy
