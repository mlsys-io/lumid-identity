package handler

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// Version reports the build provenance of the running binary so we can
// tell what commit is actually deployed (closing the code↔running-binary
// drift gap). Like Healthz it's unauthenticated — the values are baked in
// at image-build time via GIT_SHA / BUILD_TIME (deploy/Dockerfile ARGs).
func Version(c *gin.Context) {
	commit := os.Getenv("GIT_SHA")
	if commit == "" {
		commit = "unknown"
	}
	builtAt := os.Getenv("BUILD_TIME")
	if builtAt == "" {
		builtAt = "unknown"
	}
	c.JSON(http.StatusOK, gin.H{
		"service":  "lumid-identity",
		"commit":   commit,
		"built_at": builtAt,
	})
}
