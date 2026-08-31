package handler

import (
	"errors"
	"testing"
)

// MySQL 1213/1205 are retryable BY DESIGN — the server's own message says "try
// restarting transaction". This path had no retry, so a deadlock surfaced as a
// 500 and a completed cycle's result was discarded (measured 2026-08-31: a
// home-k3s cycle ran, produced a real digest, posted, and was thrown away).
func TestIsRetryableTxConflict(t *testing.T) {
	retryable := []string{
		"Error 1213 (40001): Deadlock found when trying to get lock; try restarting transaction",
		"Error 1205 (HY000): Lock wait timeout exceeded; try restarting transaction",
		// Wording-only match, in case a driver reformats the numeric prefix.
		"Deadlock found when trying to get lock",
	}
	for _, s := range retryable {
		if !isRetryableTxConflict(errors.New(s)) {
			t.Errorf("expected retryable: %q", s)
		}
	}

	// Everything else must NOT be retried. Retrying a constraint violation or a
	// syntax error just multiplies the damage and delays the real error.
	notRetryable := []string{
		"Error 1062 (23000): Duplicate entry 'x' for key 'PRIMARY'",
		"Error 1146 (42S02): Table 'lumid.me_app_intents' doesn't exist",
		"context deadline exceeded",
		"invalid connection",
	}
	for _, s := range notRetryable {
		if isRetryableTxConflict(errors.New(s)) {
			t.Errorf("expected NOT retryable: %q", s)
		}
	}

	if isRetryableTxConflict(nil) {
		t.Error("nil must not be retryable")
	}
}

func TestRetryTxConflictStopsOnSuccess(t *testing.T) {
	calls := 0
	err := retryTxConflict("test", func() error {
		calls++
		if calls < 3 {
			return errors.New("Error 1213 (40001): Deadlock found when trying to get lock")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetryTxConflictDoesNotRetryOtherErrors(t *testing.T) {
	calls := 0
	want := errors.New("Error 1062 (23000): Duplicate entry")
	err := retryTxConflict("test", func() error { calls++; return want })
	if calls != 1 {
		t.Fatalf("a non-retryable error must be returned on the first attempt, got %d calls", calls)
	}
	if !errors.Is(err, want) {
		t.Fatalf("expected the original error back, got %v", err)
	}
}

func TestRetryTxConflictIsBounded(t *testing.T) {
	calls := 0
	err := retryTxConflict("test", func() error {
		calls++
		return errors.New("Error 1213 (40001): Deadlock found")
	})
	if calls != meIntentTxAttempts {
		t.Fatalf("expected exactly %d attempts, got %d", meIntentTxAttempts, calls)
	}
	if err == nil {
		t.Fatal("a persistently deadlocking write must still surface an error, not a silent success")
	}
}
