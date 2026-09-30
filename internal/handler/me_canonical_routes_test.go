package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Registering every route must not panic: gin rejects two wildcards with
// different names in one path position (e.g. /agents/:agent vs /agents/:app)
// at startup, and only at startup.
func TestRegisterDoesNotPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Register panicked: %v", r)
		}
	}()
	Register(gin.New())
}

func TestCanonicalRoutesExistAndOldOnesAreDeprecated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r)
	want := map[string]bool{
		"GET /api/v1/me/agents/:agent/workflows/:workflow":         true,
		"PATCH /api/v1/me/agents/:agent/workflows/:workflow":       true,
		"DELETE /api/v1/me/agents/:agent/workflows/:workflow":      true,
		"POST /api/v1/me/agents/:agent/workflows/:workflow/run":    true,
		"POST /api/v1/me/agents/:agent/workflows/:workflow/cancel": true,
		"POST /api/v1/me/runs/:run_id/feedback":                    true,
	}
	for _, ri := range r.Routes() {
		delete(want, ri.Method+" "+ri.Path)
	}
	for missing := range want {
		t.Errorf("route not registered: %s", missing)
	}

	// An old route still works and names its successor. Unauthenticated, so the
	// handler itself answers 401 — the header is set before it runs.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/me/loops/qr/backtest/run", strings.NewReader("{}")))
	if w.Header().Get("Deprecation") != "true" ||
		!strings.Contains(w.Header().Get("Link"), "/api/v1/me/agents/:agent/workflows/:workflow/run") {
		t.Errorf("old run route headers = %v", w.Header())
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/me/agents/qr/workflows/backtest/run", strings.NewReader("{}")))
	if w.Header().Get("Deprecation") != "" || w.Code == http.StatusNotFound {
		t.Errorf("canonical run route: code=%d headers=%v", w.Code, w.Header())
	}
}

func TestWorkflowRunRejectsUnknownMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/w/:agent/:workflow/run", MeWorkflowRun)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/w/a/b/run", strings.NewReader(`{"mode":"later"}`)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("mode later = %d, want 400", w.Code)
	}
}

func TestRunFeedbackRejectsUnknownVerdict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/runs/:run_id/feedback", MeRunFeedback)
	w0 := httptest.NewRecorder()
	r.ServeHTTP(w0, httptest.NewRequest(http.MethodPost, "/runs/n8n:x/feedback", strings.NewReader(`{}`)))
	if w0.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated feedback = %d, want 401", w0.Code)
	}
	for _, tc := range []struct {
		id, verdict string
		ok          bool
	}{
		{"scheduled:a:b:t", "promote", true},
		{"scheduled:a::t", "discard", true}, // workflow may be empty
		{"n8n:x", "succeeded", true},        // MeRunMark judges the id itself
		{"n8n:x", "promote", false},
		{"scheduled:a:b:t", "meh", false},
		{"scheduled:a:b:latest", "good", true},
		{"scheduled:a:b:t", "revamp", true},
		{"scheduled:a:b:t", "branch", true},
		{"scheduled:a::t", "good", false}, // a rating lands in one workflow's run
		{"n8n:x", "branch", false},
	} {
		_, err := feedbackTarget(tc.id, tc.verdict)
		if (err == nil) != tc.ok {
			t.Errorf("feedbackTarget(%q, %q) err=%v, want ok=%v", tc.id, tc.verdict, err, tc.ok)
		}
	}
}

// Each verdict reaches the handler that records it, with that handler's body.
// The delegates are replaced by recorders so only the routing is under test.
func TestRunFeedbackRoutesEachVerdict(t *testing.T) {
	for _, tc := range []struct {
		verdict, kind string
		agent, wf, ts string
	}{
		{"good", "rating", "qr", "backtest", "20260930T010203Z"},
		{"revamp", "review", "qr", "backtest", "20260930T010203Z"},
		{"branch", "branch", "qr", "backtest", "20260930T010203Z"},
		{"discard", "branch-state", "qr", "backtest", "20260930T010203Z"},
	} {
		got, err := feedbackTarget("scheduled:"+tc.agent+":"+tc.wf+":"+tc.ts, tc.verdict)
		if err != nil || got != (feedbackRoute{tc.kind, tc.agent, tc.wf, tc.ts}) {
			t.Errorf("%s -> %+v %v", tc.verdict, got, err)
		}
	}
}
