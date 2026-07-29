package handler

// Generic per-user "act as <sub>" bridge credential minter.
//
//   POST /api/v1/internal/mint-user-token   (X-Bridge-Secret)
//
// claude-proxy is the single authenticated gateway for LumidOS tool traffic:
// it introspects the caller's claude:proxy PAT, resolves the user, and then
// needs to call a backend (xpcloud / FlowMesh / Lumilake / lumid-data) AS THAT
// USER without ever exposing a broad backend PAT to the client or the sandbox.
// This endpoint mints a short-lived RS256 JWT for the resolved sub, audience-
// and scope-constrained, which the backends already validate via JWKS /
// introspect. It reuses common.IssueBridgeJWT — the same facility behind the
// scoped session-bearer and the opsagent/cluster bridges — not a parallel auth.

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type mintUserTokenBody struct {
	Sub        string   `json:"sub"`
	Audience   string   `json:"audience"`
	Scopes     []string `json:"scopes"`
	TTLSeconds int      `json:"ttl_seconds"`
}

// InternalMintUserToken — POST /api/v1/internal/mint-user-token (X-Bridge-Secret).
// Returns a short-lived bearer that authenticates as `sub` against `audience`.
func InternalMintUserToken(c *gin.Context) {
	var b mintUserTokenBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if b.Sub == "" || b.Audience == "" {
		fail(c, http.StatusBadRequest, 1400, "sub and audience required")
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", b.Sub).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1404, "user not found")
		return
	}
	ttl := time.Duration(b.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > 15*time.Minute {
		ttl = 15 * time.Minute // clamp: these are gateway-forward creds, keep them short
	}
	tok, _, exp, err := common.IssueBridgeJWT(u.ID, u.Email, u.Role, b.Audience, b.Scopes, ttl)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "minted", "data": gin.H{
		"token":      tok,
		"expires_at": exp.UTC().Format(time.RFC3339),
	}})
}
