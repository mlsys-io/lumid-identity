package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ok / fail shape match LQA's ret_code envelope so frontends that
// already parse LQA responses keep working without a rewrite.
func ok(c *gin.Context, msg string, data any) {
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": msg, "data": data})
}

func fail(c *gin.Context, status, code int, msg string) {
	c.JSON(status, gin.H{"ret_code": code, "message": msg})
}

// bearerToken pulls the Bearer value out of Authorization, or the
// lm_session cookie if no header. Used by PAT + account endpoints.
func bearerToken(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if ck, err := c.Cookie("lm_session"); err == nil {
		return ck
	}
	return ""
}

// isEmail is the laziest possible validator — "something@something".
// We intentionally don't RFC-5322-parse; the real validation is the
// verification email itself.
func isEmail(s string) bool {
	at := strings.Index(s, "@")
	if at < 1 {
		return false
	}
	dot := strings.Index(s[at:], ".")
	return dot > 1
}
