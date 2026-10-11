package handler

// Regression tests for the Defect: enqueueAppFileWrite answered 202 the
// instant the row was inserted, before the scheduler had even looked at it.
// A picker build with no app_file_write dispatch case always marks the row
// "failed" within one claim cycle, so that 202 promised a write that could
// never land — the next GET of the same file 404'd, and a DELETE "succeeded"
// against a file that was never removed. enqueueAppFileWrite now waits
// (bounded) for the picker's answer and reports it honestly: 200 only once
// the row is really "done", a real error when it is "failed", and 202 only
// when the answer is still genuinely unknown (no picker running within the
// window). DB-backed: skips without TEST_MYSQL_DSN (see setupStaleReadsDB).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/models"
)

// enqueueAppFileWriteFor drives enqueueAppFileWrite through a throwaway gin
// context and decodes the ret_code/message/data envelope it writes.
func enqueueAppFileWriteFor(t *testing.T, userSub, app, rel, op, content, baseSHA string) (code int, env map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/x", nil)
	enqueueAppFileWrite(c, userSub, app, rel, op, content, baseSHA)
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v (%s)", err, w.Body.String())
	}
	return w.Code, env
}

func TestEnqueueAppFileWrite_SchedulerDone_Returns200NotTheOld202(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-ok", "ok-app")
	got := fakePicker(t, db, "user-ok", appFileWriteAction, "done",
		`{"ok":true,"action":"app_file_write","data":{"ok":true}}`)

	code, env := enqueueAppFileWriteFor(t, "user-ok", "ok-app", "prompts/p.md", "write", "hello", "")
	if p := <-got; p["path"] != "prompts/p.md" || p["content"] != "hello" {
		t.Fatalf("picker saw payload %v", p)
	}
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 once the scheduler reports done: %v", code, env)
	}
	data, _ := env["data"].(map[string]any)
	if data["saved"] != true || data["status"] != "done" || data["queued"] != false {
		t.Fatalf("data = %v", data)
	}

	// The row must still exist (status done) — appFileOverlays reads it later.
	// A read-intent row would have been deleted; a write-intent row must not.
	var row models.MeAppIntent
	if err := db.Where("user_sub = ? AND action = ?", "user-ok", appFileWriteAction).Take(&row).Error; err != nil {
		t.Fatalf("write intent row missing after a successful wait: %v", err)
	}
	if row.Status != "done" {
		t.Fatalf("row status = %q, want done", row.Status)
	}
}

func TestEnqueueAppFileWrite_SchedulerFailed_NeverReturns202(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-fail", "fail-app")
	fakePicker(t, db, "user-fail", appFileWriteAction, "failed",
		`{"ok":false,"error":"unknown action: app_file_write"}`)

	code, env := enqueueAppFileWriteFor(t, "user-fail", "fail-app", "prompts/p.md", "write", "hello", "")
	if code == http.StatusAccepted {
		t.Fatalf("got 202 for a write the scheduler already marked failed: %v", env)
	}
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (an honest failure, not a 2xx): %v", code, env)
	}
	msg, _ := env["message"].(string)
	if !strings.Contains(msg, "unknown action: app_file_write") {
		t.Fatalf("message = %q, want the scheduler's own error surfaced", msg)
	}
	if rc, _ := env["ret_code"].(float64); rc == 0 {
		t.Fatalf("ret_code = %v, want non-zero on a failed save", env["ret_code"])
	}
}

// A "done" row whose envelope actually says ok:false (should not happen given
// InternalMeIntentResult, but the handler must not trust the status string
// alone) must still be reported as a failure, not a save.
func TestEnqueueAppFileWrite_DoneRowWithOKFalse_IsStillAFailure(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-weird", "weird-app")
	fakePicker(t, db, "user-weird", appFileWriteAction, "done",
		`{"ok":false,"error":"base_sha mismatch"}`)

	code, env := enqueueAppFileWriteFor(t, "user-weird", "weird-app", "prompts/p.md", "write", "hello", "stale")
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %v", code, env)
	}
	if msg, _ := env["message"].(string); !strings.Contains(msg, "base_sha mismatch") {
		t.Fatalf("message = %q", msg)
	}
}

// When the picker has not answered within the window at all, the row is
// genuinely still unknown — today's 202/poll contract is the honest answer,
// not a regression of the fix.
func TestEnqueueAppFileWrite_NoPickerWithinWindow_Returns202Queued(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-slow", "slow-app")
	prevTimeout := readIntentDefaultTimeout
	readIntentDefaultTimeout = 80 * time.Millisecond
	t.Cleanup(func() { readIntentDefaultTimeout = prevTimeout })

	code, env := enqueueAppFileWriteFor(t, "user-slow", "slow-app", "prompts/p.md", "write", "hello", "")
	if code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 while the scheduler has not answered yet: %v", code, env)
	}
	data, _ := env["data"].(map[string]any)
	if data["queued"] != true || data["saved"] != false || data["status"] != "pending" {
		t.Fatalf("data = %v", data)
	}

	var row models.MeAppIntent
	if err := db.Where("user_sub = ? AND action = ?", "user-slow", appFileWriteAction).Take(&row).Error; err != nil {
		t.Fatalf("row missing: %v", err)
	}
	if row.Status != "pending" {
		t.Fatalf("row status = %q, want still pending", row.Status)
	}
}

// Delete follows the same op; a DELETE must not claim 202/success either when
// the scheduler reports the delete failed.
func TestEnqueueAppFileWrite_Delete_SchedulerFailed_NeverReturns202(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-del", "del-app")
	fakePicker(t, db, "user-del", appFileWriteAction, "failed",
		`{"ok":false,"error":"unknown action: app_file_write"}`)

	code, env := enqueueAppFileWriteFor(t, "user-del", "del-app", "prompts/p.md", "delete", "", "")
	if code == http.StatusAccepted {
		t.Fatalf("delete got 202 for a write the scheduler already marked failed: %v", env)
	}
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %v", code, env)
	}
}
