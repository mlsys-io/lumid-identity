package handler

// Synchronous READ intents: ask the scheduler for something only its disk has,
// and wait for the answer.
//
// Owner writes already travel to the scheduler as intents (me_app_file_intent.go,
// me_app_file_ops_intent.go) because identity mounts no tenant volume. Several
// READS still looked at a local tenant tree that does not exist on a cloud pod,
// so they answered empty — the next-actions recommender, the lineage tree, the
// improvements ledger behind the intent audit. runReadIntent routes those
// through the same queue: insert, poll the row until the picker posts its
// result, return the result's `data`.
//
// Read rows are bookkeeping, not history. A completed one is DELETED by the
// caller that read it, so reads never clutter the intent history, the Studio
// pending cards or admin insights. A caller that times out leaves its row (the
// picker still completes it); every read action row older than
// readIntentRetention is deleted opportunistically by later calls.
//
// A short in-process cache (readIntentCacheTTL) plus in-flight de-duplication
// keep a page that polls from enqueueing one intent per poll.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// readIntentActions are the picker actions that only read. Listed so every
// surface that enumerates intents can leave them out, and the claim can serve
// them first (a caller is blocked on each one).
var readIntentActions = []string{"trajectory_query", "app_file_read", cycleReadAction}

func isReadIntentAction(a string) bool {
	for _, r := range readIntentActions {
		if r == a {
			return true
		}
	}
	return false
}

const (
	readIntentCacheTTL   = 15 * time.Second
	readIntentRetention  = time.Hour
	readIntentSweepEvery = time.Minute
)

// Vars so tests can tighten them.
var (
	readIntentDefaultTimeout = 20 * time.Second
	readIntentPollEvery      = 250 * time.Millisecond
)

// errReadIntentTimeout: the scheduler did not answer within the timeout.
var errReadIntentTimeout = errors.New("the scheduler did not answer in time — try again in a moment")

// readIntentFailed: the scheduler answered, and the read failed there.
type readIntentFailed struct{ msg string }

func (e *readIntentFailed) Error() string { return e.msg }

type readIntentCacheEntry struct {
	data map[string]any
	exp  time.Time
}

type readIntentCall struct {
	done chan struct{}
	data map[string]any
	err  error
}

var (
	readIntentMu        sync.Mutex
	readIntentCache     = map[string]readIntentCacheEntry{}
	readIntentInflight  = map[string]*readIntentCall{}
	readIntentLastSweep time.Time
)

// resetReadIntentCache clears the cache (tests).
func resetReadIntentCache() {
	readIntentMu.Lock()
	readIntentCache = map[string]readIntentCacheEntry{}
	readIntentMu.Unlock()
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// runReadIntent enqueues a read `action` for userSub and waits (up to timeout,
// or ctx) for the picker's result. It returns the result's `data` object — a
// fresh top-level copy the caller may modify. A picker-side failure is a
// *readIntentFailed; no answer in time is errReadIntentTimeout.
func runReadIntent(ctx context.Context, userSub, action string, payload map[string]any, timeout time.Duration) (map[string]any, error) {
	if common.DB == nil {
		return nil, errors.New("no database")
	}
	if timeout <= 0 {
		timeout = readIntentDefaultTimeout
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	key := userSub + "\x00" + action + "\x00" + string(pj)

	readIntentMu.Lock()
	if e, hit := readIntentCache[key]; hit {
		if time.Now().Before(e.exp) {
			readIntentMu.Unlock()
			return copyMap(e.data), nil
		}
		delete(readIntentCache, key)
	}
	if call, busy := readIntentInflight[key]; busy {
		readIntentMu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return nil, call.err
			}
			return copyMap(call.data), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &readIntentCall{done: make(chan struct{})}
	readIntentInflight[key] = call
	sweep := time.Since(readIntentLastSweep) > readIntentSweepEvery
	if sweep {
		readIntentLastSweep = time.Now()
	}
	readIntentMu.Unlock()

	if sweep {
		sweepReadIntents()
	}
	call.data, call.err = doReadIntent(ctx, userSub, action, payload, timeout)

	readIntentMu.Lock()
	delete(readIntentInflight, key)
	if call.err == nil {
		readIntentCache[key] = readIntentCacheEntry{data: call.data, exp: time.Now().Add(readIntentCacheTTL)}
	}
	readIntentMu.Unlock()
	close(call.done)
	if call.err != nil {
		return nil, call.err
	}
	return copyMap(call.data), nil
}

func doReadIntent(ctx context.Context, userSub, action string, payload map[string]any, timeout time.Duration) (map[string]any, error) {
	p := copyMap(payload) // insertIntent mutates (strips "bearer")
	id, err := insertIntent(action, userSub, p)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(readIntentPollEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errReadIntentTimeout
		case <-tick.C:
		}
		var row models.MeAppIntent
		if err := common.DB.Select("id", "status", "result").Where("id = ?", id).
			Take(&row).Error; err != nil {
			continue // transient; the deadline bounds this
		}
		if row.Status != "done" && row.Status != "failed" {
			continue
		}
		common.DB.Where("id = ?", id).Delete(&models.MeAppIntent{})
		return readIntentData(row.Status, row.Result)
	}
}

// readIntentData turns a completed row's result envelope — the picker posts
// {ok, action, data:{...}} or {ok:false, error} — into data or an error.
func readIntentData(status, result string) (map[string]any, error) {
	var env struct {
		OK    bool           `json:"ok"`
		Error string         `json:"error"`
		Data  map[string]any `json:"data"`
	}
	_ = json.Unmarshal([]byte(result), &env)
	if status == "done" && env.OK {
		if env.Data == nil {
			env.Data = map[string]any{}
		}
		return env.Data, nil
	}
	msg := env.Error
	if msg == "" && env.Data != nil {
		msg, _ = env.Data["error"].(string)
	}
	if msg == "" {
		msg = "the read failed on the scheduler"
	}
	return nil, &readIntentFailed{msg: msg}
}

// sweepReadIntents deletes read rows nobody will read any more: completed rows
// whose caller timed out, and rows the picker never reached.
func sweepReadIntents() {
	common.DB.Where("action IN ? AND created_at < ?", readIntentActions, time.Now().Add(-readIntentRetention)).
		Delete(&models.MeAppIntent{})
}

// ginReqCtx is the request context, or Background for a context-less caller
// (a tool dispatched outside an HTTP request, tests).
func ginReqCtx(c *gin.Context) context.Context {
	if c == nil || c.Request == nil {
		return context.Background()
	}
	return c.Request.Context()
}
