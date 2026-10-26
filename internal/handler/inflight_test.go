package handler

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestMaxInFlightShedsBeyondCapAndExemptsHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MaxInFlight(2))
	release := make(chan struct{})
	r.GET("/slow", func(c *gin.Context) { <-release; c.Status(http.StatusOK) })
	r.GET("/livez", func(c *gin.Context) { c.Status(http.StatusOK) })

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ { // fill the cap
		wg.Add(1)
		go func() { defer wg.Done(); r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/slow", nil)) }()
	}
	time.Sleep(50 * time.Millisecond)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/slow", nil))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("3rd request: got %d Retry-After=%q, want 503 + Retry-After: 1", w.Code, w.Header().Get("Retry-After"))
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/livez", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/livez must never be shed, got %d", w.Code)
	}

	close(release)
	wg.Wait()
	w = httptest.NewRecorder() // slots freed: served again
	r.GET("/fast", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.ServeHTTP(w, httptest.NewRequest("GET", "/fast", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("after release: got %d, want 200", w.Code)
	}
}

func TestMaxInFlightZeroDisables(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MaxInFlight(0))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cap 0 should disable shedding, got %d", w.Code)
	}
}
