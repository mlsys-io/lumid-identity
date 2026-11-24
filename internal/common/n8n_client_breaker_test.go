package common

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func refusedBaseURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens now: connect is refused
	return "http://" + addr
}

// A failed CONNECT short-circuits later calls for the cool-down.
func TestN8nBreakerTripsOnConnectFailure(t *testing.T) {
	ResetN8nBreaker()
	t.Cleanup(ResetN8nBreaker)
	cli := &N8nClient{BaseURL: refusedBaseURL(t), HTTP: &http.Client{Timeout: time.Second}}

	_, err := cli.ListExecutions(context.Background(), "", "", "")
	if err == nil || errors.Is(err, ErrN8nUnreachable) {
		t.Fatalf("first call: err = %v, want a real connect error", err)
	}
	t0 := time.Now()
	_, err = cli.ListExecutions(context.Background(), "", "", "")
	if !errors.Is(err, ErrN8nUnreachable) {
		t.Fatalf("second call: err = %v, want ErrN8nUnreachable", err)
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		t.Fatalf("short-circuit took %v", d)
	}
	// Scoped per base URL: another n8n is unaffected.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer ok.Close()
	other := &N8nClient{BaseURL: ok.URL, HTTP: &http.Client{Timeout: time.Second}}
	if _, err := other.ListExecutions(context.Background(), "", "", ""); err != nil {
		t.Fatalf("other base URL: %v", err)
	}
}

// Slow-but-connected is NOT unreachable, and the caller cancelling is not
// evidence about n8n at all.
func TestN8nBreakerIgnoresSlowAnswersAndCallerCancel(t *testing.T) {
	ResetN8nBreaker()
	t.Cleanup(ResetN8nBreaker)
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(release); slow.Close() }()
	cli := &N8nClient{BaseURL: slow.URL, HTTP: &http.Client{Timeout: 5 * time.Second}}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := cli.ListExecutions(ctx, "", "", ""); err == nil || errors.Is(err, ErrN8nUnreachable) {
		t.Fatalf("slow call: err = %v", err)
	}
	if n8nInCooldown(slow.URL, time.Now()) {
		t.Fatal("a slow answer after a successful connect tripped the breaker")
	}

	dead := refusedBaseURL(t)
	cli2 := &N8nClient{BaseURL: dead, HTTP: &http.Client{Timeout: time.Second}}
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	_, _ = cli2.ListExecutions(cctx, "", "", "")
	if n8nInCooldown(dead, time.Now()) {
		t.Fatal("a caller-cancelled request tripped the breaker")
	}
}

// A success clears a cool-down.
func TestN8nBreakerResetsOnSuccess(t *testing.T) {
	ResetN8nBreaker()
	t.Cleanup(ResetN8nBreaker)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	n8nMarkUnreachable(srv.URL, time.Now().Add(-2*n8nUnreachableCooldown)) // already expired
	cli := &N8nClient{BaseURL: srv.URL, HTTP: &http.Client{Timeout: time.Second}}
	if _, err := cli.ListExecutions(context.Background(), "", "", ""); err != nil {
		t.Fatal(err)
	}
	n8nBreaker.Lock()
	_, still := n8nBreaker.until[srv.URL]
	n8nBreaker.Unlock()
	if still {
		t.Fatal("success did not clear the cool-down entry")
	}
}
