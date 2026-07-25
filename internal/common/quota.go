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
	"strings"
	"time"

	"gorm.io/gorm"

	"lumid_identity/models"
)

const (
	DefaultCyclesDaily     = 100
	DefaultLLMTokensDaily  = 500_000
	DefaultGmailSendsDaily = 200
	DefaultSlackPostsDaily = 100

	// Claude account-pool per-user caps — rolling windows mirroring
	// Anthropic's own 5h/7d shape (uncached input + output tokens).
	DefaultClaude5hTokens = 4_000_000
	DefaultClaude7dTokens = 40_000_000
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
	// kind=claude_proxy only: the user's pool utilization after this charge,
	// as a percentage of the rolling 5h/7d token caps.
	FiveHourPct *float64 `json:"five_hour_pct,omitempty"`
	SevenDayPct *float64 `json:"seven_day_pct,omitempty"`
}

// poolCapApplies reports whether a model's usage counts against the Anthropic
// account-pool caps.
//
// An EMPTY model means claude-proxy's pre-request gate (a dry-run carrying no
// model and zero tokens) — it must be gated. Treating "" as non-Anthropic is
// what silently disabled quota enforcement entirely; see quota_gate_test.go.
func poolCapApplies(model string) bool {
	return model == "" || strings.HasPrefix(model, "claude")
}

// ClaudePoolLimits reads the env-tunable per-user pool caps.
func ClaudePoolLimits() (fiveH, sevenD int) {
	return envIntPos("LUMID_QUOTA_CLAUDE_5H_TOKENS", DefaultClaude5hTokens),
		envIntPos("LUMID_QUOTA_CLAUDE_7D_TOKENS", DefaultClaude7dTokens)
}

// ClaudePoolWindows returns one user's claude_proxy token usage over the
// rolling 5h and 7d windows.
func ClaudePoolWindows(db *gorm.DB, userSub string) (fiveH, sevenD int, err error) {
	now := time.Now().UTC()
	rows := []struct {
		Win    string
		Tokens int
	}{}
	err = db.Raw(`
		SELECT CASE WHEN ts >= ? THEN '5h' ELSE '7d' END AS win,
		       COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens
		FROM   usage_events
		WHERE  user_sub = ? AND kind = 'claude_proxy' AND ts >= ?
		GROUP  BY win`, now.Add(-5*time.Hour), userSub, now.Add(-7*24*time.Hour)).Scan(&rows).Error
	if err != nil {
		return 0, 0, err
	}
	for _, r := range rows {
		if r.Win == "5h" {
			fiveH += r.Tokens
		}
		sevenD += r.Tokens // 5h window is inside the 7d window
	}
	return fiveH, sevenD, nil
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
	var fivePct, sevenPct *float64
	switch req.Kind {
	case "claude_proxy":
		// Rolling 5h/7d windows (not midnight-daily) — mirrors the Anthropic
		// account quota shape the pool itself is subject to.
		//
		// Non-Anthropic models (kimi-k3, z-ai/glm-5.2, etc.) don't consume the
		// Anthropic token pool — skip the cap check and just record the event.
		//
		// `req.Model != ""` is load-bearing. claude-proxy's PRE-REQUEST gate is a
		// dry-run with no model and zero tokens (gateUser →
		// chargeUser(sub,"","",0,0,true)), and an empty string is not
		// "claude"-prefixed — so this bypass silently swallowed the gate and
		// EVERY user was served regardless of quota. The cap was effectively
		// unenforced from the commit that introduced the bypass until this fix;
		// only a named non-Anthropic model may skip.
		if !poolCapApplies(req.Model) {
			break
		}
		cap5, cap7 := ClaudePoolLimits()
		used5, used7, werr := ClaudePoolWindows(db, req.UserSub)
		if werr != nil {
			return ChargeRes{}, werr
		}
		tok := req.InputTokens + req.OutputTokens
		if used5+tok > cap5 {
			deny = "quota_exceeded_claude_5h"
		} else if used7+tok > cap7 {
			deny = "quota_exceeded_claude_7d"
		}
		p5 := float64(used5+tok) / float64(cap5) * 100
		p7 := float64(used7+tok) / float64(cap7) * 100
		fivePct, sevenPct = &p5, &p7
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
		Allowed:     deny == "",
		DenyReason:  deny,
		Limits:      limits,
		ResetAt:     NextResetAt().Format(time.RFC3339),
		FiveHourPct: fivePct,
		SevenDayPct: sevenPct,
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
