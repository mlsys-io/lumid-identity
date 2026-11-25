package handler

// GET /me/apps/:app/queue — the caller's run queue, read on the scheduler via
// a queue_read intent. The handler tests stand in for the scheduler with
// meQueueReadIntent; the DB-backed one runs the real intent round-trip and
// skips without TEST_MYSQL_DSN (see setupStaleReadsDB).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

type queueReadCall struct {
	user, action string
	payload      map[string]any
}

func stubQueueRead(t *testing.T, data map[string]any, err error) *[]queueReadCall {
	t.Helper()
	calls := &[]queueReadCall{}
	prev := meQueueReadIntent
	meQueueReadIntent = func(_ context.Context, user, action string, payload map[string]any, _ time.Duration) (map[string]any, error) {
		*calls = append(*calls, queueReadCall{user, action, payload})
		if err != nil {
			return nil, err
		}
		return copyMap(data), nil
	}
	t.Cleanup(func() { meQueueReadIntent = prev })
	return calls
}

func queueTestToken(t *testing.T, sub string) string {
	t.Helper()
	testKeys(t)
	tok, _, _, err := common.IssueJWT(sub, sub+"@example.test", "user", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func queueGet(t *testing.T, path, tok string) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/me/apps/:app/queue", MeAppQueue)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var env map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: body is not JSON: %s", path, w.Body.String())
	}
	if _, has := env["ret_code"]; !has {
		t.Fatalf("%s: not the ret_code envelope: %s", path, w.Body.String())
	}
	return w.Code, env
}

func TestMeAppQueuePassesRowsThrough(t *testing.T) {
	tok := queueTestToken(t, "user-q")
	calls := stubQueueRead(t, map[string]any{
		"app": "q-app",
		"rows": []any{
			map[string]any{"req_id": "r1", "loop": "main", "experiment_id": "e1", "state": "queued",
				"remaining": 3.0, "ran": 1.0, "priority": 5.0, "submitted_at": "2026-11-25T01:00:00Z",
				"updated_at": "2026-11-25T01:01:00Z", "last_error": nil, "branch_label": "b",
				"variant_id": "v1", "position": 1.0,
				// A field the picker adds later must reach the client untouched.
				"added_later": map[string]any{"x": 1.0}},
			map[string]any{"req_id": "r2", "state": "running"},
			"not a row", // dropped, not passed through as junk
		},
		"progress": map[string]any{"queued": 1.0, "running": 1.0},
	}, nil)

	code, env := queueGet(t, "/api/v1/me/apps/q-app/queue", tok)
	if code != http.StatusOK || env["ret_code"] != 0.0 {
		t.Fatalf("HTTP %d %v", code, env)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d read intents, want 1", len(*calls))
	}
	call := (*calls)[0]
	if call.user != "user-q" || call.action != "queue_read" {
		t.Fatalf("intent = %s/%s, want user-q/queue_read", call.user, call.action)
	}
	if want := map[string]any{"app": "q-app", "limit": 50}; !reflect.DeepEqual(call.payload, want) {
		t.Fatalf("payload = %v, want %v", call.payload, want)
	}
	data := env["data"].(map[string]any)
	rows := data["rows"].([]any)
	if data["app"] != "q-app" || len(rows) != 2 || data["count"] != 2.0 {
		t.Fatalf("data = %v", data)
	}
	r1 := rows[0].(map[string]any)
	if r1["req_id"] != "r1" || r1["position"] != 1.0 || r1["variant_id"] != "v1" {
		t.Fatalf("row 1 = %v", r1)
	}
	if later, _ := r1["added_later"].(map[string]any); later["x"] != 1.0 {
		t.Fatalf("an unknown row field was dropped: %v", r1)
	}
	if p := data["progress"].(map[string]any); p["queued"] != 1.0 {
		t.Fatalf("progress = %v", p)
	}
}

// An empty answer is an empty queue: rows [] and progress {}, never null.
func TestMeAppQueueEmptyIsArrayNotNull(t *testing.T) {
	tok := queueTestToken(t, "user-q")
	stubQueueRead(t, map[string]any{"app": "q-app"}, nil)
	code, env := queueGet(t, "/api/v1/me/apps/q-app/queue", tok)
	if code != http.StatusOK {
		t.Fatalf("HTTP %d %v", code, env)
	}
	data := env["data"].(map[string]any)
	if rows, okk := data["rows"].([]any); !okk || len(rows) != 0 {
		t.Fatalf("rows = %#v, want []", data["rows"])
	}
	if p, okk := data["progress"].(map[string]any); !okk || len(p) != 0 {
		t.Fatalf("progress = %#v, want {}", data["progress"])
	}
}

func TestMeAppQueueTimeoutIs504(t *testing.T) {
	tok := queueTestToken(t, "user-q")
	stubQueueRead(t, nil, errReadIntentTimeout)
	code, env := queueGet(t, "/api/v1/me/apps/q-app/queue", tok)
	if code != http.StatusGatewayTimeout || env["message"] != errReadIntentTimeout.Error() {
		t.Fatalf("HTTP %d %v; want 504 with %q", code, env, errReadIntentTimeout.Error())
	}
}

func TestMeAppQueueSchedulerErrorIs502(t *testing.T) {
	tok := queueTestToken(t, "user-q")
	stubQueueRead(t, nil, &readIntentFailed{msg: "unknown action: queue_read"})
	code, env := queueGet(t, "/api/v1/me/apps/q-app/queue", tok)
	if code != http.StatusBadGateway || env["message"] != "unknown action: queue_read" {
		t.Fatalf("HTTP %d %v; want 502 with the scheduler's message", code, env)
	}
}

func TestMeAppQueueRejectsBadAppAndAnonymous(t *testing.T) {
	tok := queueTestToken(t, "user-q")
	calls := stubQueueRead(t, map[string]any{}, nil)
	for _, p := range []string{
		"/api/v1/me/apps/bad%20app/queue",
		"/api/v1/me/apps/a..b/queue",
		"/api/v1/me/apps/a%24b/queue",
	} {
		if code, env := queueGet(t, p, tok); code != http.StatusBadRequest || env["message"] != "invalid app" {
			t.Errorf("%s: HTTP %d %v, want 400 invalid app", p, code, env)
		}
	}
	if code, _ := queueGet(t, "/api/v1/me/apps/q-app/queue", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous: HTTP %d, want 401", code)
	}
	if len(*calls) != 0 {
		t.Fatalf("%d read intents queued for rejected requests", len(*calls))
	}
}

// queue_read is a read: kept out of intent listings and served first.
func TestQueueReadIsAReadIntent(t *testing.T) {
	if !isReadIntentAction("queue_read") {
		t.Fatal("queue_read is not in readIntentActions")
	}
}

// The real round-trip: the row is queued for the caller, the picker answers,
// the row is deleted.
func TestMeAppQueueViaScheduler(t *testing.T) {
	db := setupStaleReadsDB(t)
	tok := queueTestToken(t, "user-Q")
	got := fakePicker(t, db, "user-Q", queueReadAction, "done", `{"ok":true,"action":"queue_read","data":`+
		`{"app":"q-app","rows":[{"req_id":"r1","state":"queued"}],"progress":{"queued":1}}}`)
	code, env := queueGet(t, "/api/v1/me/apps/q-app/queue", tok)
	if code != http.StatusOK {
		t.Fatalf("HTTP %d %v", code, env)
	}
	if p := <-got; p["app"] != "q-app" || p["limit"] != 50.0 {
		t.Fatalf("picker payload = %v", p)
	}
	if rows := env["data"].(map[string]any)["rows"].([]any); len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	if n := countIntents(db, queueReadAction); n != 0 {
		t.Fatalf("%d queue_read rows left, want 0", n)
	}
}
