// Package ledger is the memory of the system: the rolling pool of nodes worth
// re-checking, run history, and per-source yield.
//
// Pool entries decay. Re-check intervals widen with observed stability, consecutive
// failures back off exponentially, and entries age out — the predecessor wrote a
// last_seen timestamp it never read, so a node surviving every third run lived
// forever and 30% of the pool was re-verified at full cost while failing.
//
// Pool identity is the structural node identity, never the rendered subscription
// line: the old key embedded a GeoIP flag, so one lookup flip forked the entry
// (INV-22).
package ledger
