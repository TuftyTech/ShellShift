package publish

import (
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"time"

	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/policy"
)

// NodeRow is what the dashboard is allowed to know about one node.
//
// It is a projection, not a record. Host, port, credential and server name are absent by
// construction: the site exists to show that verification happened, not to republish somebody
// else nodes in a second form. A visitor who wants the endpoint takes the subscription
// (GHOST-048).
type NodeRow struct {
	// ID is the short display identifier, eight hex characters of the identity hash.
	ID string `json:"id"`
	// CC is the two-letter country code, absent when unknown. Never a string meaning
	// unknown: an absent value and a value that means unknown are different things.
	CC        string `json:"cc,omitempty"`
	Protocol  string `json:"proto"`
	Transport string `json:"transport"`
	Class     string `json:"class"`
	// LatencyMS is the measured proof latency, absent when not measured.
	LatencyMS int `json:"latency_ms,omitempty"`
	// Mbps is measured throughput, absent when not measured. Absent is distinct from
	// slow: a failed measurement must never be published as a zero (INV-36).
	Mbps float64 `json:"mbps,omitempty"`
	// VerifiedAt is when the proof happened.
	VerifiedAt time.Time `json:"verified_at"`
	// Streak is consecutive runs passed, which is honest and unflattering about how
	// churny public proxies are.
	Streak int `json:"streak,omitempty"`
	// Attest records which stages ran and how they went, so the claim is checkable rather
	// than asserted.
	Attest map[string]string `json:"attest,omitempty"`
	// Detail is everything else known about the node, for the card. Absent when the node's URI
	// could not be rendered, and absent from a payload written before version 2.
	Detail *NodeDetail `json:"detail,omitempty"`
}

// Funnel is the pipeline rendered honestly: everything collected, and what each stage
// removed. The predecessor emitted no such breakdown, which is why its dashboard could
// only assert that verification happened.
type Funnel struct {
	Collected int `json:"collected"`
	Decoded   int `json:"decoded"`
	// Candidates is the distinct nodes left after deduplication, and it is a stage rather
	// than a derived figure because the drop from Decoded to it is real: a popular node
	// appears in several feeds at once.
	Candidates int `json:"candidates"`
	Policy     int `json:"policy"`
	Reached    int `json:"reached"`
	Proven     int `json:"proven"`
	// Rejected counts lines decoding refused, and Failed counts nodes verification refused.
	// Both are totals of the per-reason maps the run also reports.
	//
	// They are stored rather than left to the caller to add up because they are two of the
	// terminal buckets Unaccounted checks, and an accounting invariant that depends on the
	// reader summing the right map correctly is not an invariant (INV-40).
	Rejected int `json:"rejected"`
	Failed   int `json:"failed"`
	// Duplicates counts decoded lines that named a node another feed had already offered.
	//
	// Before this existed the figure was unaccounted for: it was counted in Decoded and then
	// dropped by the deduplication map with no counter, so Decoded did not equal the number
	// of candidates and the difference was attributed nowhere. That is the same defect this
	// project criticises in its predecessor telemetry, applied to deduplication instead of
	// verification (INV-40).
	Duplicates int `json:"duplicates,omitempty"`
	// Deferred counts candidates the ledger said were not worth a full verification yet.
	Deferred int `json:"deferred,omitempty"`
	// NotAttempted counts candidates that were due but never verified because the run ran
	// out of budget.
	//
	// This exists because the funnel without it is dishonest in exactly the way the
	// predecessor telemetry was. A live run with a four-minute budget and 54,222 due
	// candidates finished half of them; the remaining half was indistinguishable from
	// nodes that had failed the first stage, and the published yield would have been
	// wrong by a factor of two with nothing to indicate it (INV-41, INV-42).
	NotAttempted int `json:"not_attempted,omitempty"`
	// BudgetExhausted records that the run stopped early.
	BudgetExhausted bool `json:"budget_exhausted,omitempty"`
}

// Unaccounted returns how many collected lines ended in no bucket at all. Zero means the
// funnel adds up.
//
// Every line a feed offered reaches exactly one terminal disposition: decoding refused it,
// another feed had already offered it, the ledger deferred it, the budget ran out before it
// was tried, verification failed it, or it was proven. So
//
//	Collected == Rejected + Duplicates + Deferred + NotAttempted + Failed + Proven
//
// Policy and Reached are deliberately absent: they are pass counts at intermediate stages,
// and a node that passes policy and then fails the proof is terminal in Failed only.
//
// This exists as a computation rather than a comment because of what happened to the same
// rule in the predecessor. It was written down — "otherwise a mixed batch silently loses
// them from every counter" at _legacy/angra_core.go:590 — and it was still broken by
// construction: Survived was finalised before a champion round that then incremented the
// same failure counters, so the arithmetic could not hold and nothing said so (INV-40).
func (f Funnel) Unaccounted() int {
	return f.Collected - (f.Rejected + f.Duplicates + f.Deferred + f.NotAttempted +
		f.Failed + f.Proven)
}

// Data is the file the dashboard fetches.
type Data struct {
	Version int `json:"version"`
	// GeneratedAt is the run time, and the only thing the freshness indicator reads. The
	// predecessor rendered a hardcoded "active" badge with no data binding at all.
	GeneratedAt time.Time `json:"generated_at"`
	// RunSeconds is how long the run took.
	RunSeconds float64 `json:"run_seconds"`
	Funnel     Funnel  `json:"funnel"`
	// Method names what was actually done, in words, so the attestation surface can show
	// it instead of a slogan.
	Method string `json:"method"`
	// Engine identifies the tunnel implementation and its version.
	Engine string    `json:"engine"`
	Nodes  []NodeRow `json:"nodes"`
	// Rejections counts decode refusals by reason, which is the signal that separates a
	// parser regression from upstream churn.
	Rejections map[string]int `json:"rejections,omitempty"`
	// ClassReasons counts why each proven node landed in the class it did.
	//
	// It is published rather than only printed because the page is the only surface anybody
	// looks at, and without it a "whitelisted — 0 nodes" card cannot be told apart from
	// "the whitelist feed failed to load, so the check never ran". Those are opposite
	// facts: one says no node qualified, the other says nothing was asked. The run report
	// has carried this histogram since the beginning and threw it away at publication,
	// which is the same defect this project calls out in its predecessor — a count with no
	// reason beside it — applied to the one place a reader would see it.
	ClassReasons map[string]int `json:"class_reasons,omitempty"`
}

// DataVersion is bumped when the shape changes, so a stale dashboard can notice.
//
// 2 added the per-node detail. A version 1 payload still renders: the page simply offers no card,
// because the data behind it is not there — which is the honest degradation for a file that was
// written before the feature existed.
const DataVersion = 2

// Extras carries the per-run and per-node facts that do not come off the verdict.
//
// A struct rather than more positional parameters, and the comment it replaces is the reason: three
// of these fields are map[string]int, so slotting a new one between two existing ones silently
// reordered every call site the compiler could not check. Adding a field here cannot do that.
type Extras struct {
	// Rejections counts decode refusals by reason, Streaks is consecutive passes per node key,
	// ClassReasons counts why nodes landed outside the whitelisted class.
	Rejections   map[string]int
	Streaks      map[string]int
	ClassReasons map[string]int
	// History is what the ledger remembers about a node, keyed by node key.
	History map[string]NodeHistory
	// Covers is what the masking prover saw, keyed by the server name it probed. One entry
	// serves every node naming that site, which is also why the proof is cheap.
	Covers map[string]policy.CoverCert
}

// NodeHistory is the ledger's memory of one node.
type NodeHistory struct {
	Proofs    int
	Failures  int
	FirstSeen time.Time
}

// NodeDetail is everything the project knows about one node.
//
// It exists because the dashboard could show that verification happened and nothing about what was
// verified: a reader looking at a node they are using had no way to ask "is this the one, and what
// is it". Every field here was already measured or already fetched — the card publishes what the
// run knew and threw away, and adds no request to anybody's infrastructure.
//
// The endpoint is in here, and that is a deliberate narrowing of GHOST-048. The rule said the
// dashboard must not republish somebody else's node in a second form; what it protected against
// was an indexable page that reads as a directory of other people's servers with their passwords
// in it. That protection is intact — this travels in the payload, a machine file beside the
// subscription that has published the same bytes from the beginning, and the rendered page carries
// none of it. The interface masks the credential until a reader asks for it.
//
// Absent stays absent (INV-36): a value that was not measured is omitted, never published as zero.
type NodeDetail struct {
	// URI is the subscription line for this node, byte for byte what sub_all.txt carries.
	URI string `json:"uri"`

	Server     string `json:"server"`
	Port       int    `json:"port"`
	PortRange  string `json:"port_range,omitempty"`
	Credential string `json:"credential,omitempty"`
	Method     string `json:"method,omitempty"`
	Security   string `json:"security,omitempty"`
	SNI        string `json:"sni,omitempty"`
	Host       string `json:"host,omitempty"`
	Path       string `json:"path,omitempty"`
	PublicKey  string `json:"pbk,omitempty"`
	ShortID    string `json:"sid,omitempty"`
	Plugin     string `json:"plugin,omitempty"`

	Fingerprint string   `json:"fp,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Flow        string   `json:"flow,omitempty"`
	AlterID     int      `json:"aid,omitempty"`
	Obfuscation string   `json:"obfs,omitempty"`
	Encoding    string   `json:"packet_encoding,omitempty"`

	// Stages is the verification record: which ran, how each went and how long it took.
	Stages []StageRow `json:"stages,omitempty"`
	Bytes  int64      `json:"bytes,omitempty"`

	Proofs    int        `json:"proofs,omitempty"`
	Failures  int        `json:"failures,omitempty"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`

	// Source is the feed's host, never its URL. A feed URL in a public file is a line somebody
	// copies, and this project's predecessor published all 118 of them.
	Source string `json:"source,omitempty"`

	// Addr is the address verification actually dialled, and the rest of this block is whose
	// network that address belongs to.
	Addr        string `json:"addr,omitempty"`
	CountryName string `json:"country,omitempty"`
	City        string `json:"city,omitempty"`
	Timezone    string `json:"tz,omitempty"`
	ASN         string `json:"asn,omitempty"`
	ASName      string `json:"asname,omitempty"`
	ISP         string `json:"isp,omitempty"`
	Org         string `json:"org,omitempty"`
	Reverse     string `json:"ptr,omitempty"`

	// ClassReason is why this node is in its class, in the classifier's own words.
	ClassReason string `json:"class_reason,omitempty"`
	// Cover is the certificate the masking proof saw, absent when there was no proof to make.
	Cover *CoverRow `json:"cover,omitempty"`
}

// StageRow is one verification stage as published.
type StageRow struct {
	Stage   string `json:"stage"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	MS      int    `json:"ms,omitempty"`
}

// CoverRow is the cover site's certificate, translated out of policy.CoverCert so the payload does
// not inherit that package's shape.
type CoverRow struct {
	Issuer  string     `json:"issuer,omitempty"`
	Subject string     `json:"subject,omitempty"`
	From    *time.Time `json:"from,omitempty"`
	To      *time.Time `json:"to,omitempty"`
	TLS     string     `json:"tls,omitempty"`
	Proven  bool       `json:"proven"`
}

// BuildData assembles the dashboard payload.
func BuildData(entries []Entry, funnel Funnel, generatedAt time.Time, runFor time.Duration,
	engine string, x Extras) Data {

	// The same codes and labels the subscription files use, computed from the same set, so the
	// URI in a card is the line a reader would have copied out of sub_all.txt rather than a second
	// rendering of it that could drift.
	codes := ShortCodes(entries)

	rows := make([]NodeRow, 0, len(entries))
	for _, e := range entries {
		row := NodeRow{
			ID:         e.Node.Short(),
			CC:         e.Node.Country,
			Protocol:   string(e.Node.Identity.Protocol),
			Transport:  string(e.Node.Identity.Transport),
			Class:      string(e.Node.Class),
			VerifiedAt: e.Verdict.At,
			Streak:     x.Streaks[e.Node.Key()],
			Attest:     attestation(e.Verdict),
		}
		if e.Verdict.Measured.Latency > 0 {
			row.LatencyMS = int(e.Verdict.Measured.Latency.Milliseconds())
		}
		if e.Verdict.Measured.Mbps > 0 {
			row.Mbps = e.Verdict.Measured.Mbps
		}
		row.Detail = detailFor(e, codes[e.Node.Key()], x)
		rows = append(rows, row)
	}
	// Sorted so the payload is byte-stable under regeneration (PERF-041).
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	return Data{
		Version:     DataVersion,
		GeneratedAt: generatedAt,
		RunSeconds:  runFor.Seconds(),
		Funnel:      funnel,
		Method: "each node was dialled in-process through a sing-box outbound and made to " +
			"complete an HTTPS request whose certificate chain was verified",
		Engine:       engine,
		Nodes:        rows,
		Rejections:   x.Rejections,
		ClassReasons: x.ClassReasons,
	}
}

// detailFor assembles one node's card, or returns nil when the URI cannot be rendered.
//
// nil rather than a partial card: the URI is the one field the card cannot be useful without, and
// a card that shows a node's whole configuration except the line you would connect with is a card
// that invites the reader to reconstruct it by hand.
func detailFor(e Entry, code string, x Extras) *NodeDetail {
	uri, err := Encode(e.Node, Label(e.Node, code))
	if err != nil {
		return nil
	}
	id := e.Node.Identity
	d := &NodeDetail{
		URI:         uri,
		Server:      id.Server,
		Port:        int(id.Port),
		PortRange:   id.PortRange,
		Credential:  id.Credential,
		Method:      id.Method,
		Security:    string(id.Security),
		SNI:         id.SNI,
		Host:        id.Host,
		Path:        id.Path,
		PublicKey:   id.PublicKey,
		ShortID:     id.ShortID,
		Plugin:      id.Plugin,
		Fingerprint: e.Node.Fingerprint,
		ALPN:        e.Node.ALPN,
		Flow:        e.Node.Flow,
		AlterID:     e.Node.AlterID,
		Obfuscation: e.Node.Obfuscation,
		Encoding:    e.Node.PacketEncoding,
		Bytes:       e.Verdict.Measured.Bytes,
		Source:      sourceHost(e.Node.Source),
		Addr:        e.Node.Addr,
		CountryName: e.Node.CountryName,
		City:        e.Node.City,
		Timezone:    e.Node.Timezone,
		ASN:         e.Node.ASN,
		ASName:      e.Node.ASName,
		ISP:         e.Node.ISP,
		Org:         e.Node.Org,
		Reverse:     e.Node.Reverse,
		ClassReason: e.Node.ClassReason,
	}
	for _, st := range e.Verdict.Stages {
		row := StageRow{Stage: string(st.Stage), Outcome: string(st.Outcome), Reason: st.Reason}
		if st.Elapsed > 0 {
			row.MS = int(st.Elapsed.Milliseconds())
		}
		d.Stages = append(d.Stages, row)
	}
	if h, ok := x.History[e.Node.Key()]; ok {
		d.Proofs, d.Failures = h.Proofs, h.Failures
		if !h.FirstSeen.IsZero() {
			at := h.FirstSeen.UTC()
			d.FirstSeen = &at
		}
	}
	// The cover is looked up by the name the classifier probed, so a node that named no site has
	// no certificate rather than an empty one.
	if name := policy.CoverName(e.Node); name != "" {
		if c, ok := x.Covers[name]; ok {
			row := &CoverRow{Issuer: c.Issuer, Subject: c.Subject, TLS: c.TLSVersion, Proven: c.Proven}
			if !c.NotBefore.IsZero() {
				from := c.NotBefore.UTC()
				row.From = &from
			}
			if !c.NotAfter.IsZero() {
				to := c.NotAfter.UTC()
				row.To = &to
			}
			d.Cover = row
		}
	}
	return d
}

// sourceHost reduces a feed URL to its host.
//
// The host is the useful half — "which feed offered this node" — and the path is the half that
// makes a line somebody copies. The predecessor published all 118 of its feed URLs into a public
// tree while also holding them in a repository secret, so the secret protected nothing.
func sourceHost(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

func attestation(v model.Verdict) map[string]string {
	if len(v.Stages) == 0 {
		return nil
	}
	out := make(map[string]string, len(v.Stages))
	for _, s := range v.Stages {
		out[string(s.Stage)] = string(s.Outcome)
	}
	return out
}

// WriteData serialises the payload.
func WriteData(w io.Writer, d Data) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	return enc.Encode(d)
}
