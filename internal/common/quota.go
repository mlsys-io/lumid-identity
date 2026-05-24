package common

// Tier-1 quota enforcement — the dogfood gate.
//
// Five caps, all per-tenant, all rolled at midnight UTC:
//   1. cycles/day                                   (kind=cycle_start)
//   2. LLM input+output tokens/day                  (kind=cycle_llm)
//   3. Gmail sends/day                              (kind=external_api, endpoint=gmail.send)
//   4. Slack posts/day                              (kind=external_api, endpoint=slack.post)
//   5. Wall-time per cycle (10 min)                 — enforced by the picker, not here
//   6. Concurrent cycles per tenant (5)             — enforced by an in-mem semaphore in
//                                                     the scheduler process, not here
//
// CPU + memory caps are deferred to Phase D1 (per-cycle Docker isolation).
//
// Records flow into the existing usage_events table (models/usage_event.go).
// CheckAndCharge is a non-transactional COUNT-then-INSERT — the race window
// can let one extra event slip past the cap. Acceptable for dogfood; Phase D
// upgrades to SERIALIZABLE transactions if it matters.

import (
	"os"
	"strconv"
	"time"

	"gorm.io/gorm"

	"lumid_identity/models"
)

const (
	DefaultCyclesDaily      = 100
	DefaultLLMTokensDaily   = 500_000
	DefaultGmailSendsDaily  = 200
	DefaultSlackPostsDaily  = 100
)

// Limits captures the headline numbers the UI surfaces alongside today's totals.
type Limits struct {
	CyclesDaily     int `json:"cycles_daily"`
	LLMTokensDaily  int `json:"llm_tokens_daily"`
	GmailSendsDaily int `json:"gmail_sends_daily"`
	SlackPostsDaily int `json:"slack_posts_daily"`
}

// DefaultLimits reads env overrides; falls back to the constants above.
func DefaultLimits() Limits {
	return Limits{
		CyclesDaily:     envIntPos("LUMID_QUOTA_CYCLES_DAILY", DefaultCyclesDaily),
		LLMTokensDaily:  envIntPos("LUMID_QUOTA_LLM_TOKENS_DAILY", DefaultLLMTokensDaily),
		GmailSendsDaily: envIntPos("LUMID_QUOTA_GMAIL_DAILY", DefaultGmailSendsDaily),
		SlackPostsDaily: envIntPos("LUMID_QUOTA_SLACK_DAILY", DefaultSlackPostsDaily),
	}
}

func envIntPos(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// Totals captures usage so far today across the four gated kinds.
type Totals struct {
	Cycles     int `json:"cycles"`
	LLMTokens  int `json:"llm_tokens"`
	GmailSends int `json:"gmail_sends"`
	SlackPosts int `json:"slack_posts"`
}

// TodayBound returns midnight-UTC at the start of today.
func TodayBound() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// NextResetAt is when the per-day counters roll back to zero.
func NextResetAt() time.Time {
	return TodayBound().Add(24 * time.Hour)
}

// FetchTodayTotals aggregates usage_events for one user from midnight UTC.
// One grouped query — keeps the hot path off N round-trips.
func FetchTodayTotals(db *gorm.DB, userSub string) (Totals, error) {
	var t Totals
	rows := []struct {
		Kind     string
		Endpoint string
		Tokens   int
		Cnt      int
	}{}
	err := db.Raw(`
		SELECT kind                              AS kind,
		       COALESCE(endpoint, '')            AS endpoint,
		       COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens,
		       COUNT(*)                          AS cnt
		FROM   usage_events
		WHERE  user_sub = ? AND ts >= ?
		GROUP  BY kind, endpoint`, userSub, TodayBound()).Scan(&rows).Error
	if err != nil {
		return t, err
	}
	for _, r := range rows {
		switch r.Kind {
		case "cycle_start":
			t.Cycles += r.Cnt
		case "cycle_llm":
			t.LLMTokens += r.Tokens
		case "external_api":
			switch r.Endpoint {
			case "gmail.send":
				t.GmailSends += r.Cnt
			case "slack.post":
				t.SlackPosts += r.Cnt
			}
		}
	}
	return t, nil
}

// ChargeReq is the input shape for CheckAndCharge.
type ChargeReq struct {
	UserSub      string
	Kind         string // cycle_start | cycle_llm | external_api | chat | ...
	Endpoint     string // for cycle_llm: "<app>.<loop>"; for external_api: "gmail.send" | "slack.post"
	Model        string
	InputTokens  int
	OutputTokens int
	Count        int // for cycle_start / external_api; defaults to 1 when 0
	CostCents    int
	DryRun       bool
	Meta         string // optional JSON blob
}

// ChargeRes is the output. Same shape served by /internal/usage/charge.
type ChargeRes struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
	Today      Totals `json:"today"`
	Limits     Limits `json:"limits"`
	ResetAt    string `json:"reset_at"`
}

// CheckAndCharge enforces the four daily caps and (on allowed && !DryRun)
// writes a usage_events row. Unknown kinds are recorded but ungated.
func CheckAndCharge(db *gorm.DB, req ChargeReq) (ChargeRes, error) {
	limits := DefaultLimits()
	totals, err := FetchTodayTotals(db, req.UserSub)
	if err != nil {
		return ChargeRes{}, err
	}

	after := totals
	deny := ""
	switch req.Kind {
	case "cycle_start":
		n := req.Count
		if n <= 0 {
			n = 1
		}
		after.Cycles += n
		if after.Cycles > limits.CyclesDaily {
			deny = "quota_exceeded_cycles_daily"
		}
	case "cycle_llm":
		tok := req.InputTokens + req.OutputTokens
		after.LLMTokens += tok
		if after.LLMTokens > limits.LLMTokensDaily {
			deny = "quota_exceeded_llm_tokens_daily"
		}
	case "external_api":
		n := req.Count
		if n <= 0 {
			n = 1
		}
		switch req.Endpoint {
		case "gmail.send":
			after.GmailSends += n
			if after.GmailSends > limits.GmailSendsDaily {
				deny = "quota_exceeded_gmail_daily"
			}
		case "slack.post":
			after.SlackPosts += n
			if after.SlackPosts > limits.SlackPostsDaily {
				deny = "quota_exceeded_slack_daily"
			}
		}
	}

	res := ChargeRes{
		Allowed:    deny == "",
		DenyReason: deny,
		Limits:     limits,
		ResetAt:    NextResetAt().Format(time.RFC3339),
	}
	if !res.Allowed {
		// On deny: report current state, not the would-be after-state.
		res.Today = totals
		return res, nil
	}
	res.Today = after

	if req.DryRun {
		return res, nil
	}
	ev := models.UsageEvent{
		UserSub:      req.UserSub,
		Ts:           time.Now().UTC(),
		Kind:         req.Kind,
		Endpoint:     req.Endpoint,
		Model:        req.Model,
		InputTokens:  req.InputTokens,
		OutputTokens: req.OutputTokens,
		CostCents:    req.CostCents,
		Meta:         req.Meta,
	}
	if err := db.Create(&ev).Error; err != nil {
		return ChargeRes{}, err
	}
	return res, nil
}
