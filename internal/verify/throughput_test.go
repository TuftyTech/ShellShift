package verify

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/model"
	"github.com/tuftytech/shellshift/internal/tunnel"
)

func meterAgainst(t *testing.T, srv *httptest.Server, path string) *Meter {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	m := NewMeter()
	m.URL = srv.URL + path
	m.RootCAs = pool
	return m
}

func target() tunnel.Target {
	return tunnel.Target{Node: testNode(), Server: netip.MustParseAddr("127.0.0.1")}
}

// A full-size transfer produces a figure.
func TestMeasureReportsThroughput(t *testing.T) {
	payload := strings.Repeat("x", 64<<10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 8; i++ {
			_, _ = w.Write([]byte(payload))
		}
	}))
	defer srv.Close()

	mbps, bytes, err := meterAgainst(t, srv, "/down").Measure(context.Background(), directDialer{}, target())
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if bytes < 256<<10 {
		t.Fatalf("transferred %d bytes, expected at least the validity floor", bytes)
	}
	if mbps <= 0 {
		t.Fatal("throughput must be positive")
	}
	if mbps > 3000 {
		t.Fatalf("throughput %v exceeds the clamp", mbps)
	}
}

// A sample below the validity floor is rejected rather than believed. Publishing it would put
// a stalled transfer on the page as a slow node (INV-36).
func TestTruncatedSampleIsRejected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 8<<10)))
	}))
	defer srv.Close()

	mbps, bytes, err := meterAgainst(t, srv, "/down").Measure(context.Background(), directDialer{}, target())
	if err == nil {
		t.Fatal("a truncated sample must be rejected")
	}
	if mbps != 0 {
		t.Fatalf("a rejected sample must report no figure, got %v", mbps)
	}
	if bytes == 0 {
		t.Fatal("the byte count should still be reported so the truncation is visible")
	}
}

// A transfer going nowhere is abandoned rather than waiting out the budget for a number that
// would be discarded anyway.
func TestSlowTransferIsAbandonedEarly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 100; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, _ = w.Write([]byte("x"))
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	m := meterAgainst(t, srv, "/down")
	m.EarlyAbortAfter = 200 * time.Millisecond
	m.EarlyAbortBelow = 64 << 10

	started := time.Now()
	_, _, err := m.Measure(context.Background(), directDialer{}, target())
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("a transfer going nowhere must be abandoned")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("took %v: the early abort did not fire", elapsed)
	}
}

// INV-35. The clock starts after the response headers, not at the request.
//
// The predecessor included handshake and time-to-first-byte, which understated fast nodes with
// high latency — worst for exactly the nodes worth having — and while speed was still a filter
// it discarded good ones. The test makes the pre-header delay large relative to the transfer:
// if the clock included it, the reported figure would be several times lower.
func TestClockStartsAfterTheResponseHeaders(t *testing.T) {
	const preHeaderDelay = 400 * time.Millisecond
	payload := strings.Repeat("x", 64<<10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Stall before writing anything, so the delay lands before the headers.
		time.Sleep(preHeaderDelay)
		for i := 0; i < 8; i++ {
			_, _ = w.Write([]byte(payload))
		}
	}))
	defer srv.Close()

	m := meterAgainst(t, srv, "/down")
	m.EarlyAbortAfter = 10 * time.Second // the stall must not trip the early abort either

	started := time.Now()
	mbps, bytes, err := m.Measure(context.Background(), directDialer{}, target())
	wall := time.Since(started)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}

	// What the figure would have been had the clock started at the request.
	if wall < preHeaderDelay {
		t.Fatalf("the server did not stall: wall time %v", wall)
	}
	includingDelay := float64(bytes) * 8 / (wall.Seconds() * 1_000_000)
	// The measured figure must be clearly better than the one that includes the stall.
	// Two-fold is a wide margin against scheduling noise while still failing decisively if
	// the clock moves back to the request.
	if mbps < includingDelay*2 {
		t.Fatalf("throughput %.1f Mbps is close to the figure including the pre-header "+
			"stall (%.1f Mbps): the clock appears to start before the headers",
			mbps, includingDelay)
	}
}

// INV-37. Speed ranks, it does not eliminate. A failed measurement must not un-prove a node:
// surviving the proof is what keeps it. The predecessor had 40 parallel downloads sharing one
// runner uplink, understating every figure, and a min_speed filter then cut live nodes.
func TestFailedMeasurementKeepsTheNodeProven(t *testing.T) {
	proof := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proof.Close()

	pool := x509.NewCertPool()
	pool.AddCert(proof.Certificate())
	prover := NewProver()
	prover.URLs = []string{proof.URL + "/generate_204"}
	prover.RootCAs = pool

	e := New(directDialer{}, prover)
	e.SkipReach = true
	e.Resolver = fixedResolver("93.184.216.34")
	// A meter pointed at nothing: the measurement fails.
	e.Meter = NewMeter()
	e.Meter.URL = "https://127.0.0.1:1/down"
	e.Budget.Throughput = 500 * time.Millisecond

	v := e.Verify(context.Background(), testNode())
	if !v.Proven {
		t.Fatal("a failed measurement must not un-prove a node")
	}
	if outcome, ok := v.Pass(model.StageThroughput); !ok || outcome != "fail" {
		t.Fatalf("throughput stage outcome = %q recorded = %v", outcome, ok)
	}
	if v.Measured.Mbps != 0 {
		t.Fatalf("a failed measurement must report no figure, got %v", v.Measured.Mbps)
	}
}
