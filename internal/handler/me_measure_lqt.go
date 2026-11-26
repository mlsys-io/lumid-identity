package handler

// The lqt-backtest instrument (central measurement, phase C, 2026-11-26).
//
// A backtest is submitted to the LQT backtest job API AS THE CALLER (their
// minted lqt:strategy PAT — a claim is tenant-scoped by the credential), and
// read back with the same account's credential. Two things make it different
// from the simulator:
//
//   - The gateway paces each tenant (one unsettled claim, a minimum interval
//     between submits) and answers 409. That is a QUEUE here, not a failure:
//     the row stays `queued` with not_before, and the first read after that
//     time submits it.
//   - Whether a result may be reused is known only once it settles, from the
//     worker's receipt (services/lqt-backtest-worker main.rs). A replay reads
//     the submitting tenant's OWN signals, plus a shared publisher's only for
//     names the tenant does not publish (replay.rs, migration 0085) — and the
//     receipt does not say which. So:
//       reusable  = replay "pg_tape" + window pinned by the claim (until in
//                   the past) + the harness version the key assumed
//       global    = reusable and no recorded signals were read
//       otherwise reusable by the submitting tenant only; a synthetic replay
//       or an unpinned window is never reused.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const lqtBacktestPath = "/api/research/backtests"

var (
	lqtClaimRe      = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
	lqtRetryAfterRe = regexp.MustCompile(`retry_after_secs\W{0,3}(\d+)`)
)

// lqtGatewayBase: where the backtest job API answers (the public host routes
// /api/research/* to lqt-api-gateway).
func lqtGatewayBase() string {
	if b := strings.TrimSpace(os.Getenv("LQT_GATEWAY_BASE")); b != "" {
		return strings.TrimRight(b, "/")
	}
	return "https://lum.id"
}

// lqtHarness: the worker's HARNESS_VERSION the key assumes. Bump it (env) when
// the worker's harness changes; a receipt with another version is not reused.
func lqtHarness() string {
	if v := strings.TrimSpace(os.Getenv("MEASURE_LQT_HARNESS")); v != "" {
		return v
	}
	return "3"
}

func lqtBacktestPlan(in map[string]any) (measurePlan, error) {
	strategy, isMap := in["strategy"].(map[string]any)
	if !isMap || len(strategy) == 0 {
		return measurePlan{}, errors.New("strategy must be a non-empty JSON object (the backtest job API's strategy body)")
	}
	symbol, _ := in["symbol"].(string)
	if symbol == "" {
		symbol, _ = strategy["symbol"].(string)
	}
	if symbol == "" || len(symbol) > 200 {
		return measurePlan{}, errors.New("symbol is required (top level or strategy.symbol)")
	}
	material := map[string]any{"strategy": strategy, "symbol": symbol}
	cacheable := false
	if t, ok := lqtParseUntil(strategy["until"]); ok && t.Before(time.Now().Add(-time.Minute)) {
		cacheable = true
	}
	if !cacheable {
		// Without a pinned past window the worker anchors the replay to "now",
		// so no two runs are the same measurement: give this one its own key.
		material["once"] = lqtNonce()
	}
	name, _ := in["name"].(string)
	return measurePlan{version: "harness-" + lqtHarness(), label: "harness " + lqtHarness(),
		material: material, name: fleetClip(name, 120)}, nil
}

// lqtParseUntil reads the strategy's `until`: RFC 3339, or epoch seconds /
// milliseconds / nanoseconds.
func lqtParseUntil(v any) (time.Time, bool) {
	switch u := v.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, strings.TrimSpace(u)); err == nil {
				return t, true
			}
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(u), 10, 64); err == nil {
			return lqtEpoch(n), true
		}
	case json.Number:
		if n, err := u.Int64(); err == nil {
			return lqtEpoch(n), true
		}
	case float64:
		return lqtEpoch(int64(u)), true
	}
	return time.Time{}, false
}

func lqtEpoch(n int64) time.Time {
	switch {
	case n > 1e15:
		return time.Unix(0, n)
	case n > 1e12:
		return time.UnixMilli(n)
	default:
		return time.Unix(n, 0)
	}
}

func lqtNonce() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func lqtMaterial(row *models.MeasureResult) map[string]any {
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(row.Inputs))
	dec.UseNumber()
	_ = dec.Decode(&m)
	return m
}

// lqtMeasureSubmit submits the row's backtest as `sub`. queued=true means the
// gateway is pacing this tenant: the row waits until not_before.
func lqtMeasureSubmit(row *models.MeasureResult, sub string) (queued bool, retryAfter int, err error) {
	pat := lqtStrategyPATCached(sub)
	if pat == "" {
		return false, 0, errors.New("no LQT strategy credential could be minted for this account")
	}
	m := lqtMaterial(row)
	body, _ := json.Marshal(map[string]any{"name": "measure-" + row.Key[:12], "strategy": m["strategy"],
		"symbol": m["symbol"]})
	out, code, err := lqtDoAt(lqtGatewayBase(), http.MethodPost, lqtBacktestPath, body, pat)
	if err != nil {
		return false, 0, err
	}
	if code == http.StatusConflict {
		raw, _ := json.Marshal(out)
		retry := 60
		if mm := lqtRetryAfterRe.FindStringSubmatch(string(raw)); mm != nil {
			if n, e := strconv.Atoi(mm[1]); e == nil && n > 0 {
				retry = n
			}
		}
		nb := time.Now().Add(time.Duration(retry) * time.Second)
		row.Status, row.NotBefore, row.ExecutorSub = "queued", &nb, sub
		common.DB.Model(row).Updates(map[string]any{"status": "queued", "not_before": nb, "executor_sub": sub})
		return true, retry, nil
	}
	if code < 200 || code >= 300 {
		raw, _ := json.Marshal(out)
		return false, 0, fmt.Errorf("the backtest job API refused the claim (HTTP %d): %s", code, fleetClip(string(raw), 300))
	}
	claim, _ := out["claim_id"].(string)
	if !lqtClaimRe.MatchString(claim) {
		return false, 0, errors.New("the backtest job API accepted the claim but returned no usable id")
	}
	row.Status, row.ExecutorRef, row.NotBefore = "running", "lqt:"+claim, nil
	return false, 0, common.DB.Model(row).Updates(map[string]any{"status": "running",
		"executor_ref": row.ExecutorRef, "not_before": nil}).Error
}

// lqtMeasureAdvance moves an lqt row on: submit it once pacing allows, then
// read its claim with the executor's credential. An unreachable gateway
// changes nothing.
func lqtMeasureAdvance(c *gin.Context, row *models.MeasureResult) {
	_ = c
	if row.ExecutorRef == "" {
		if row.NotBefore != nil {
			if time.Now().Before(*row.NotBefore) {
				return
			}
			if _, _, err := lqtMeasureSubmit(row, row.ExecutorSub); err != nil {
				measureSettle(row, "failed", "", err.Error())
			}
			return
		}
		if time.Since(row.ClaimedAt) > measureClaimStale {
			measureSettle(row, "failed", "", "the submission did not complete; asking again retries it")
		}
		return
	}
	claim := strings.TrimPrefix(row.ExecutorRef, "lqt:")
	pat := lqtStrategyPATCached(row.ExecutorSub)
	if pat == "" || !lqtClaimRe.MatchString(claim) {
		return
	}
	out, code, err := lqtDoAt(lqtGatewayBase(), http.MethodGet, lqtBacktestPath+"/"+claim, nil, pat)
	if err != nil || code == 0 || code >= 500 {
		return
	}
	if code == http.StatusNotFound {
		measureSettle(row, "failed", "", "the backtest claim is no longer readable")
		return
	}
	switch status, _ := out["status"].(string); status {
	case "queued", "running":
		if row.Status != "running" {
			row.Status = "running"
			common.DB.Model(row).Update("status", "running")
		}
	case "done":
		_, unpinned := lqtMaterial(row)["once"]
		scope, reusable := lqtShareScope(out, !unpinned, lqtHarness(), row.ExecutorSub)
		res, _ := canonicalJSON(map[string]any{"value": out})
		now := time.Now()
		row.Status, row.Result, row.Error, row.SettledAt = "succeeded", res, "", &now
		row.ShareScope, row.NoReuse = scope, !reusable
		common.DB.Model(row).Updates(map[string]any{"status": "succeeded", "result": res, "error": "",
			"settled_at": now, "share_scope": scope, "no_reuse": !reusable})
	default:
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = "the backtest ended " + status
		}
		measureSettle(row, "failed", "", msg)
	}
}

// lqtShareScope applies the receipt rules (see the file comment).
func lqtShareScope(claim map[string]any, pinned bool, harness, executorSub string) (string, bool) {
	rep, _ := claim["replay"].(map[string]any)
	tenant := "tenant:" + executorSub
	if rep == nil || !pinned {
		return tenant, false
	}
	str := func(k string) string { return fmt.Sprint(rep[k]) }
	reusable := str("replay") == "pg_tape" && str("tape_window_source") == "claim" && str("harness_version") == harness
	if !reusable {
		return tenant, false
	}
	if str("signals") == "recorded" {
		return tenant, true
	}
	return "global", true
}
