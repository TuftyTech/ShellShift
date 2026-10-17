// Package verify decides whether a node actually proxies traffic.
//
// The verdict is an HTTPS fetch with a verified certificate chain — not a plaintext
// HTTP 204, which a hostile or captive-portal node can forge (INV-31). Nodes that
// work only with certificate verification disabled are never published as ordinary
// nodes (INV-30).
//
// Scheduling is evidence-driven: a cheap reachability signal first, per-node
// deadlines adapted from the observed p95 connect time, probes raced concurrently
// under a single hard deadline, and early abort. There is no unconditional sleep
// anywhere in this path.
package verify
