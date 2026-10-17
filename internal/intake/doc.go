// Package intake fetches subscription sources over HTTPS.
//
// Every fetch is bounded: maximum response bytes, maximum decompressed bytes,
// maximum line length, maximum nodes per source, and a wall-clock budget per source.
// The predecessor read remote bodies with no cap at all, so a single oversized or
// highly compressible response could take a shard out of a run.
//
// Scheduling is yield-weighted, not round-robin: measured history showed one source
// producing 48% of all live nodes from 3% of the parse volume, while 85 of 118
// sources had never produced a single live node.
package intake
