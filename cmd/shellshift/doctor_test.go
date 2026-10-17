package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tuftytech/shellshift/internal/verify"
)

// proofServer answers like a captive-portal check endpoint.
func proofServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func proverAgainst(t *testing.T, srvs ...*httptest.Server) *verify.Prover {
	t.Helper()
	pool := x509.NewCertPool()
	p := verify.NewProver()
	p.URLs = nil
	for _, s := range srvs {
		pool.AddCert(s.Certificate())
		p.URLs = append(p.URLs, s.URL+"/generate_204")
	}
	p.RootCAs = pool
	p.HedgeDelay = 50 * time.Millisecond
	return p
}

// INV-55. A diagnosis requires a positive control, and a control that cannot fail is not a
// control. Both halves are exercised: they pass when the path works, and they fail for the
// reasons they exist to detect.
//
// The invariant comes from a live run where almost nothing passed and "the endpoints have
// started refusing us" was the plausible, wrong explanation. These two checks are what settled
// it in two minutes.
func TestDoctorControls(t *testing.T) {
	ctx := context.Background()

	t.Run("the direct control passes when the endpoints answer", func(t *testing.T) {
		p := proverAgainst(t, proofServer(t, http.StatusNoContent))
		if !controlDirect(ctx, p, 2*time.Second) {
			t.Fatal("the direct control failed against an endpoint that answers correctly")
		}
	})

	t.Run("the direct control fails on the wrong status", func(t *testing.T) {
		// A captive portal answering 200 instead of 204 is the case this catches: something
		// answered, but not the thing we asked.
		p := proverAgainst(t, proofServer(t, http.StatusOK))
		if controlDirect(ctx, p, 2*time.Second) {
			t.Fatal("the direct control passed on a status it must reject")
		}
	})

	t.Run("the direct control fails when nothing is listening", func(t *testing.T) {
		p := verify.NewProver()
		p.URLs = []string{"https://127.0.0.1:1/generate_204"}
		if controlDirect(ctx, p, 500*time.Millisecond) {
			t.Fatal("the direct control passed with nothing listening")
		}
	})

	t.Run("one live endpoint among failures is enough", func(t *testing.T) {
		// The prover hedges across endpoints, so one provider refusing us is not the same as
		// having no egress — and conflating those is what made working nodes look dead.
		p := proverAgainst(t, proofServer(t, http.StatusNoContent))
		p.URLs = append([]string{"https://127.0.0.1:1/generate_204"}, p.URLs...)
		if !controlDirect(ctx, p, 2*time.Second) {
			t.Fatal("one answering endpoint among failures must still pass")
		}
	})

	t.Run("the prover control passes over a working path", func(t *testing.T) {
		p := proverAgainst(t, proofServer(t, http.StatusNoContent))
		if !controlProver(ctx, p, 2*time.Second) {
			t.Fatal("the prover control failed over a path that works")
		}
	})

	t.Run("the prover control fails when the prover reaches no verdict", func(t *testing.T) {
		p := verify.NewProver()
		p.URLs = []string{"https://127.0.0.1:1/generate_204"}
		if controlProver(ctx, p, 500*time.Millisecond) {
			t.Fatal("the prover control passed without a verdict")
		}
	})
}

// The passthrough dialer is the control's mechanism: the prover must not be able to tell it from
// a node that carries traffic. If it could, the control would be testing something else.
func TestPassthroughDialerReachesTheDestination(t *testing.T) {
	srv := proofServer(t, http.StatusNoContent)
	p := proverAgainst(t, srv)

	// Proving through the passthrough dialer must produce the same result as the direct
	// control, which is what makes it a valid stand-in for a working tunnel.
	if !controlProver(context.Background(), p, 2*time.Second) {
		t.Fatal("the passthrough dialer did not reach the destination")
	}
}
