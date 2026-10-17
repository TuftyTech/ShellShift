package model

import "time"

// Class is the bypass class a node falls into.
type Class string

const (
	// ClassWhitelisted is a Reality node whose SNI belongs to a censor whitelist AND
	// whose masking has been shown to be genuine. The predecessor required only the
	// list membership, which made the class a heuristic rather than a measurement
	// (INV-32, GHOST-027).
	ClassWhitelisted Class = "wl"
	// ClassOpen is every surviving node that is not whitelisted. It is the exact
	// complement, not an independent blacklist (GHOST-029).
	ClassOpen Class = "open"
)

// Stage names a point in the verification pipeline. Stages are separate counters
// because the predecessor folded translation rejects, real L4 failures and L7 losses
// into one number that the dashboard then labelled as L4, and every tuning decision
// was made against it (INV-41).
type Stage string

const (
	StageDecode     Stage = "decode"
	StagePolicy     Stage = "policy"
	StageReach      Stage = "reach"
	StageTunnel     Stage = "tunnel"
	StageProof      Stage = "proof"
	StageThroughput Stage = "throughput"
)

// Outcome is what happened to a node at a stage.
type Outcome string

const (
	OutcomePass    Outcome = "pass"
	OutcomeFail    Outcome = "fail"
	OutcomeSkipped Outcome = "skip"
)

// StageResult records one stage for one node.
type StageResult struct {
	Stage   Stage         `json:"stage"`
	Outcome Outcome       `json:"outcome"`
	Reason  string        `json:"reason,omitempty"`
	Elapsed time.Duration `json:"elapsed_ns,omitempty"`
}

// Measurement is what was observed through a working tunnel.
type Measurement struct {
	// Latency of the proof request. Zero means not measured.
	Latency time.Duration `json:"latency_ns,omitempty"`
	// Mbps is throughput. Zero means not measured, which is distinct from slow:
	// a failed measurement must never overwrite an earlier valid figure (INV-36).
	Mbps float64 `json:"mbps,omitempty"`
	// Bytes actually transferred, so a caller can tell a truncated sample from a
	// representative one.
	Bytes int64 `json:"bytes,omitempty"`
	// Refined marks a figure produced by the larger download pass.
	Refined bool `json:"refined,omitempty"`
}

// Verdict is the full record of what was proven about a node in one run. It is a
// first-class value rather than fields mutated onto the node: the predecessor wrote
// latency and speed back onto the candidate, so there was no way to ask what happened
// to a node that failed.
type Verdict struct {
	Identity string        `json:"id"`
	Stages   []StageResult `json:"stages"`
	Measured Measurement   `json:"measured,omitempty"`
	// Proven is true only when every required stage passed. Throughput is explicitly
	// not required: surviving the proof is what keeps a node (INV-37, GHOST-020).
	Proven bool      `json:"proven"`
	At     time.Time `json:"at"`
}

// Pass reports the outcome of a stage, and whether it ran at all.
func (v Verdict) Pass(s Stage) (Outcome, bool) {
	for _, r := range v.Stages {
		if r.Stage == s {
			return r.Outcome, true
		}
	}
	return "", false
}

// FailedAt returns the first stage that failed, or an empty stage when none did.
func (v Verdict) FailedAt() (Stage, string) {
	for _, r := range v.Stages {
		if r.Outcome == OutcomeFail {
			return r.Stage, r.Reason
		}
	}
	return "", ""
}

// Node is a candidate endpoint plus everything learned about it.
type Node struct {
	Identity Identity `json:"-"`

	// Fingerprint is the uTLS fingerprint, already narrowed to the allowlist.
	Fingerprint string   `json:"fp,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	// PluginOpts are the SIP003 options, parsed and validated rather than passed
	// through as an opaque string (INV-07).
	PluginOpts map[string]string `json:"plugin_opts,omitempty"`
	// PluginOptOrder is the order the producer wrote the options in.
	//
	// It is kept because a SIP003 option list is written by a producer and read by a client,
	// and handing the client back a re-sorted list is a change we have no reason to make. The
	// order is also deterministic, so keeping it costs nothing in reproducibility.
	PluginOptOrder []string `json:"plugin_opt_order,omitempty"`
	// Obfuscation and its password, for Hysteria2. Both or neither (INV-10).
	Obfuscation         string `json:"obfs,omitempty"`
	ObfuscationPassword string `json:"-"`
	// AlterID is the VMess alterId, already coerced to a sane value (INV-03).
	AlterID int `json:"aid,omitempty"`
	// Flow is the VLESS flow control, and it is empty unless the transport is raw TCP.
	// The decoder is the only place that decides this, so the dialed configuration and
	// the published URI cannot disagree the way they did across three implementations
	// in the predecessor (INV-01).
	Flow string `json:"flow,omitempty"`

	// Country is the two-letter code, or empty when unknown. Never the string "UN":
	// an absent value and a value meaning unknown are different things.
	Country string `json:"cc,omitempty"`
	// CountryName and City are the readable place, as the geo provider gave them.
	//
	// The name is stored rather than derived from Country because deriving it means carrying a
	// table of some 250 codes, and the provider already answers with it. Both are absent when
	// unknown, and the label is built to read correctly with either or both missing — the
	// predecessor's habit of substituting a placeholder is what produced "UN" as a country.
	CountryName string `json:"country,omitempty"`
	City        string `json:"city,omitempty"`
	Class       Class  `json:"class,omitempty"`
	// Addr is the address verification actually dialled, and Timezone, ASN, ASName, ISP, Org and
	// Reverse say whose network that address is.
	//
	// They arrive from the same batch request that answers the country, so they cost nothing, and
	// they are here rather than in a side map because they are facts about this node in the same
	// sense the country is. All are absent when the lookup did not answer them.
	Addr     string `json:"addr,omitempty"`
	Timezone string `json:"tz,omitempty"`
	ASN      string `json:"asn,omitempty"`
	ASName   string `json:"asname,omitempty"`
	ISP      string `json:"isp,omitempty"`
	Org      string `json:"org,omitempty"`
	Reverse  string `json:"ptr,omitempty"`

	// ClassReason is why the node landed in that class, in the classifier's own words.
	//
	// The run has always counted these into a histogram, and the histogram answers a different
	// question: it says why a class is small, not why one node is outside it. A reader looking at
	// their own node wants the second, and publication carried only the first — so "738 nodes are
	// not on the whitelist" was on the page and "yours names a site the censor blocks anyway"
	// was not.
	ClassReason string `json:"class_reason,omitempty"`

	// PacketEncoding is the VLESS UDP packet encoding, empty when the source did not name one.
	// It reaches the engine, unlike the carried parameters below.
	PacketEncoding string `json:"packet_encoding,omitempty"`

	// Carried holds parameters this project does not act on but the visitor client may. See
	// PassThrough for why the set is named rather than open.
	Carried map[string]string `json:"carried,omitempty"`

	// Source is the feed this candidate came from, for yield accounting. It is not
	// part of identity: the same node published by two feeds is one node.
	Source string `json:"-"`
}

// Key is shorthand for the node identity key.
func (n Node) Key() string { return n.Identity.Key() }

// Short is the display identifier.
func (n Node) Short() string { return n.Identity.Short() }
