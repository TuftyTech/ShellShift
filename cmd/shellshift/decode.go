package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/tuftytech/shellshift/internal/decode"
	"github.com/tuftytech/shellshift/internal/model"
)

// runDecode reads candidate URIs from stdin and reports what was accepted, what was
// rejected and why.
//
// This exists as a first-class subcommand rather than a test helper because the
// rejection breakdown is the signal that tells a parser regression apart from upstream
// churn — the distinction the predecessor could not make.
func runDecode(args []string) error {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit accepted nodes as JSON lines")
	showRejects := fs.Bool("rejects", false, "list rejected lines with their reason")
	// Labels are percent-encoded in a subscription file because a URI fragment has to be, so
	// reading one with a text tool shows %F0%9F%87%AF rather than a flag. A client decodes it;
	// a person checking the output by hand has nothing to decode it with.
	showLabels := fs.Bool("labels", false, "print the decoded label of each line, as a client shows it")
	quiet := fs.Bool("quiet", false, "suppress the summary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var (
		total     int
		accepted  int
		byReason  = map[decode.Reason]int{}
		repairs   decode.Repairs
		seen      = map[string]int{}
		protocols = map[string]int{}
	)

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	sc := bufio.NewScanner(os.Stdin)
	// Feed lines are occasionally very long: a base64 VMess payload with a verbose
	// label can exceed the default 64 KiB token.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		total++

		res, err := decode.Decode(line)
		if err != nil {
			reason, ok := decode.ReasonOf(err)
			if !ok {
				reason = "unclassified"
			}
			byReason[reason]++
			if *showRejects {
				fmt.Fprintf(out, "REJECT\t%s\t%s\n", reason, redactURI(line))
			}
			continue
		}

		accepted++
		repairs.Add(res.Repairs)
		seen[res.Node.Key()]++
		protocols[string(res.Node.Identity.Protocol)]++

		if *showLabels {
			fmt.Fprintf(out, "%s\t%s\t%s\n", labelOf(line), res.Node.Identity.Protocol,
				channelEncryption(res.Node))
		}

		if *asJSON {
			enc, mErr := json.Marshal(struct {
				ID        string `json:"id"`
				Short     string `json:"short"`
				Protocol  string `json:"protocol"`
				Endpoint  string `json:"endpoint"`
				Transport string `json:"transport"`
				Security  string `json:"security"`
				SNI       string `json:"sni,omitempty"`
			}{
				ID:        res.Node.Key(),
				Short:     res.Node.Short(),
				Protocol:  string(res.Node.Identity.Protocol),
				Endpoint:  res.Node.Identity.Endpoint(),
				Transport: string(res.Node.Identity.Transport),
				Security:  string(res.Node.Identity.Security),
				SNI:       res.Node.Identity.SNI,
			})
			if mErr != nil {
				return mErr
			}
			fmt.Fprintf(out, "%s\n", enc)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	if *quiet {
		return nil
	}

	duplicates := 0
	for _, n := range seen {
		if n > 1 {
			duplicates += n - 1
		}
	}

	fmt.Fprintf(out, "\nlines        %d\n", total)
	fmt.Fprintf(out, "accepted     %d (%.1f%%)\n", accepted, pct(accepted, total))
	fmt.Fprintf(out, "unique       %d\n", len(seen))
	fmt.Fprintf(out, "duplicates   %d\n", duplicates)
	fmt.Fprintf(out, "repairs      %d\n", repairs.Total())

	if len(protocols) > 0 {
		fmt.Fprintf(out, "\nby protocol\n")
		for _, k := range sortedKeys(protocols) {
			fmt.Fprintf(out, "  %-14s %d\n", k, protocols[k])
		}
	}
	if len(byReason) > 0 {
		fmt.Fprintf(out, "\nrejected %d\n", total-accepted)
		reasons := make(map[string]int, len(byReason))
		for k, v := range byReason {
			reasons[string(k)] = v
		}
		for _, k := range sortedByCount(reasons) {
			fmt.Fprintf(out, "  %-42s %d\n", k, reasons[k])
		}
	}
	return nil
}

// channelEncryption says what protects the hop from the client to the node.
//
// It is not the same question as Identity.Security, which names the TLS layer. Shadowsocks has no
// TLS layer and is nevertheless encrypted, by its own AEAD cipher — reporting it as "none" answers
// the wrong question and makes an encrypted node look like a plaintext one. VLESS, VMess and
// Trojan carry no encryption of their own, so for them the TLS layer is the whole answer, and its
// absence means the traffic is readable on the wire.
func channelEncryption(n model.Node) string {
	switch n.Identity.Protocol {
	case model.ProtoShadowsocks:
		return n.Identity.Method
	case model.ProtoHysteria2:
		// Hysteria2 is TLS by definition; there is no plaintext mode (INV-11).
		return "tls (quic)"
	default:
		if n.Identity.Security == model.SecurityNone {
			// Named at length because this is the finding, not a value: nothing encrypts the hop.
			return "NONE — readable on the wire"
		}
		return string(n.Identity.Security)
	}
}

// labelOf returns the fragment of a URI, percent-decoded: what a client displays.
//
// The fragment starts at the last "#", not the first, because a credential may legitimately
// contain an unencoded one — a real trojan password of the form "xxxx#yyyy" in the corpus was
// once truncated to nothing by cutting at the first (INV-47).
func labelOf(line string) string {
	i := strings.LastIndex(line, "#")
	if i < 0 {
		return "(no label)"
	}
	raw := line[i+1:]
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		// Undecodable is shown as it stands rather than hidden: that is itself the finding.
		return raw
	}
	return decoded
}

// redactURI keeps a rejected line diagnosable without printing the credential it
// carries. Rejections are the lines most likely to end up in a log.
func redactURI(line string) string {
	scheme, rest, found := strings.Cut(line, "://")
	if !found {
		return truncate(line, 60)
	}
	if _, authority, ok := strings.Cut(rest, "@"); ok {
		return scheme + "://[credential]@" + truncate(authority, 60)
	}
	return scheme + "://" + truncate(rest, 24) + "..."
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func pct(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedByCount(m map[string]int) []string {
	out := sortedKeys(m)
	sort.SliceStable(out, func(i, j int) bool { return m[out[i]] > m[out[j]] })
	return out
}
