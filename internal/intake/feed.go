package intake

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// knownSchemes are the prefixes that make a blob recognisable as a proxy feed.
var knownSchemes = []string{
	"vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://",
}

// looksLikeFeed reports whether a blob already contains proxy links.
func looksLikeFeed(s string) bool {
	for _, scheme := range knownSchemes {
		if strings.Contains(s, scheme) {
			return true
		}
	}
	return false
}

// unwrapBase64Feed handles the convention of publishing a whole feed as one base64 blob.
//
// The decision procedure is deliberately conservative: if the text already contains proxy
// links, it is used as-is and no decoding is attempted. Only when it does not, and only
// when decoding produces something that *does* contain links, is the decoded form
// accepted. That ordering is what stops a feed containing an unrelated base64 payload
// from being mangled.
func unwrapBase64Feed(s string) (string, bool) {
	if looksLikeFeed(s) {
		return s, false
	}
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if compact == "" {
		return s, false
	}

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(compact)
		if err != nil {
			continue
		}
		if text := string(decoded); looksLikeFeed(text) {
			return text, true
		}
	}
	return s, false
}

// splitLines splits a feed into candidate lines and enforces the per-line cap.
//
// Comment lines are dropped here rather than counted as candidates and rejected later.
// Feeds carry profile headers and human notes, and counting those as candidates makes the
// collected figure a measure of file formatting rather than of offered nodes — which
// matters because that figure is the first stage of the published funnel.
//
// A feed with no newlines and one enormous line is not a feed, and treating it as one is
// how a parser ends up allocating unboundedly on a single token.
func splitLines(text string, maxLine int) (lines []string, comments int, err error) {
	normalised := strings.ReplaceAll(text, "\r\n", "\n")
	normalised = strings.ReplaceAll(normalised, "\r", "\n")

	raw := strings.Split(normalised, "\n")
	out := make([]string, 0, len(raw))
	for i, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			comments++
			continue
		}
		if maxLine > 0 && len(line) > maxLine {
			return nil, comments, fmt.Errorf("%w: line %d is %d bytes, cap is %d",
				ErrLimitExceeded, i+1, len(line), maxLine)
		}
		out = append(out, line)
	}
	return out, comments, nil
}
