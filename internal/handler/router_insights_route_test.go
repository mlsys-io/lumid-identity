package handler

// Registering the real route table catches the failure mode that only shows up
// at container start: gin panics on a wildcard conflict (e.g. a second
// /admin/apps/:id beside /admin/apps/:app), which no unit test of a handler
// would ever reach. Cheap, and it needs no database.

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisterRoutesNoConflictAndInsightsMounted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("Register panicked — route conflict: %v", p)
		}
	}()
	Register(r)

	want := "/api/v1/admin/apps/:app/insights"
	for _, ri := range r.Routes() {
		if ri.Path == want && ri.Method == "GET" {
			return
		}
	}
	t.Fatalf("route %s not registered", want)
}
