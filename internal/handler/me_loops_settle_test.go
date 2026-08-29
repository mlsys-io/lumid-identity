package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"lumid_identity/internal/common"
)

// The scheduler's result envelope is the scheduler's to shape, so the reason
// extractor has to survive every shape it might send — including ones that are
// not JSON at all. Getting this wrong means a user sees raw JSON, or worse an
// empty toast, in place of the reason their cycle did not start.
func TestIntentFailureReason(t *testing.T) {
	const generic = "the scheduler could not start this cycle"
	long := strings.Repeat("x", 400)

	for _, tc := range []struct {
		name, result, want string
	}{
		{"real failure", `{"ok":false,"error":"app 'quant-research' not installed for this user"}`,
			"app 'quant-research' not installed for this user"},
		{"empty result", "", generic},
		{"whitespace only", "   ", generic},
		{"not json", "boom", generic},
		{"json without error", `{"ok":false}`, generic},
		{"error is empty string", `{"error":"   "}`, generic},
		{"multiline keeps first line", "{\"error\":\"FileNotFoundError: no manifest\\nTraceback…\"}",
			"FileNotFoundError: no manifest"},
		{"over-long is truncated", `{"error":"` + long + `"}`, long[:300] + "…"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := intentFailureReason(tc.result); got != tc.want {
				t.Fatalf("intentFailureReason(%q)\n got: %q\nwant: %q", tc.result, got, tc.want)
			}
		})
	}
}

// runNowSettled gates a user-visible error, so its bias must be one-directional:
// it may only ever report failure when the scheduler actually said so. Every
// other condition — no DB, no id, a cancelled request — has to fall through to
// the 202 this endpoint has always returned, because turning a working dispatch
// into an error is a worse regression than the silence it replaces.
func TestRunNowSettledFailsOpen(t *testing.T) {
	prev := common.DB
	defer func() { common.DB = prev }()
	common.DB = (*gorm.DB)(nil)

	t.Run("no DB", func(t *testing.T) {
		if _, failed := runNowSettled(context.Background(), "some-id"); failed {
			t.Fatal("reported failure with no DB; must fall through to 202")
		}
	})
	t.Run("empty intent id", func(t *testing.T) {
		if _, failed := runNowSettled(context.Background(), ""); failed {
			t.Fatal("reported failure for an empty intent id")
		}
	})
	t.Run("cancelled context returns promptly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		if _, failed := runNowSettled(ctx, "some-id"); failed {
			t.Fatal("reported failure on a cancelled request")
		}
		if d := time.Since(start); d > runNowSettleWait {
			t.Fatalf("waited %v on a cancelled request; want well under %v", d, runNowSettleWait)
		}
	})
}

// The wait sits in the request path, so its bound is a product decision, not an
// accident. Pin it: a fast dispatch failure lands in 1-5s, and a user should
// never wait appreciably longer than that for a queued response.
func TestRunNowSettleWaitIsBounded(t *testing.T) {
	if runNowSettleWait < 2*time.Second {
		t.Fatalf("settle wait %v is too short to catch a 1-5s dispatch failure", runNowSettleWait)
	}
	if runNowSettleWait > 10*time.Second {
		t.Fatalf("settle wait %v blocks the request path for too long", runNowSettleWait)
	}
	if runNowPollEvery <= 0 || runNowPollEvery > runNowSettleWait {
		t.Fatalf("poll interval %v is not a sane fraction of %v", runNowPollEvery, runNowSettleWait)
	}
}
