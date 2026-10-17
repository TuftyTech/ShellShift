// Package model holds the canonical domain types shared by every other package:
// Node, Identity, Verdict, Measurement, Bundle.
//
// Two rules govern this package:
//
//  1. Identity is structural and singular. Everything that affects how a node is
//     dialed belongs in it — protocol, server, port, credential, transport, security,
//     SNI/host, Reality public key, Shadowsocks method, Hysteria2 port range. The
//     predecessor project used a five-field string that silently merged distinct
//     nodes; see INV-21.
//  2. No type here performs I/O, reads configuration, or panics at init time.
package model
