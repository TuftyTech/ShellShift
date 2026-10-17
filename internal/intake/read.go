package intake

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// readFeed consumes a feed stream, stopping at the candidate cap.
//
// The base64-wrapped convention forces one compromise: a whole-feed blob has no line
// structure, so it has to be buffered before it can be recognised. That buffering is
// bounded by the same decompressed-size allowance, and a blob that large is not a feed
// anyone publishes deliberately.
func readFeed(r io.Reader, limits Limits) (Body, error) {
	br := bufio.NewReaderSize(r, 64<<10)

	// Peek enough to tell a line-structured feed from a base64 blob without reading it all.
	head, err := br.Peek(4 << 10)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return Body{}, err
	}
	if !looksLikeFeed(string(head)) && !limits.PlainLines {
		return readWrappedFeed(br, limits)
	}

	var body Body
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64<<10), limits.MaxLineBytes+1)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			body.Comments++
			continue
		}
		if limits.MaxLineBytes > 0 && len(line) > limits.MaxLineBytes {
			return Body{}, fmt.Errorf("%w: a line exceeds %d bytes", ErrLimitExceeded, limits.MaxLineBytes)
		}
		body.Lines = append(body.Lines, line)
		body.Bytes += int64(len(line)) + 1

		if limits.MaxNodesPerSource > 0 && len(body.Lines) >= limits.MaxNodesPerSource {
			body.Truncated = true
			break
		}
	}
	if err := sc.Err(); err != nil {
		// A token longer than the buffer is the same condition as an oversized line, and
		// reporting it as a limit keeps the failure legible.
		if err == bufio.ErrTooLong {
			return Body{}, fmt.Errorf("%w: a line exceeds %d bytes", ErrLimitExceeded, limits.MaxLineBytes)
		}
		return Body{}, err
	}
	return body, nil
}

// readWrappedFeed handles the whole-feed base64 convention.
func readWrappedFeed(r io.Reader, limits Limits) (Body, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Body{}, err
	}
	text := string(raw)
	body := Body{Bytes: int64(len(raw))}
	if unwrapped, ok := unwrapBase64Feed(text); ok {
		text = unwrapped
		body.Base64Wrapped = true
	}
	lines, comments, err := splitLines(text, limits.MaxLineBytes)
	if err != nil {
		return Body{}, err
	}
	body.Comments = comments
	if limits.MaxNodesPerSource > 0 && len(lines) > limits.MaxNodesPerSource {
		lines = lines[:limits.MaxNodesPerSource]
		body.Truncated = true
	}
	body.Lines = lines
	return body, nil
}
