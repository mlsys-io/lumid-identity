package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// sessionListItem is what the UI sees: no JTI/JWT material, just what's
// needed to show a row and revoke it.
type sessionListItem struct {
	ID         string  `json:"id"`
	ClientID   string  `json:"client_id"`
	UserAgent  string  `json:"user_agent"`
	IP         string  `json:"ip"`
	CreatedAt  int64   `json:"created_at"`
	ExpiresAt  int64   `json:"expires_at"`
	Current    bool    `json:"current"`   // true if this is the session that made the request
}

// SessionsListHandler returns the caller's own active (non-revoked) sessions.
// Current session is flagged via matching the request's session JTI (if
// known to the handler chain — the session cookie is parsed upstream).
func SessionsListHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	currentJTI, _ := c.Get("session_jti") // set by session-parse middleware if applicable

	var rows []models.Session
	common.DB.Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?",
		userID, time.Now()).
		Order("created_at DESC").Find(&rows)

	out := make([]sessionListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, sessionListItem{
			ID:        r.ID,
			ClientID:  r.ClientID,
			UserAgent: r.UserAgent,
			IP:        r.IP,
			CreatedAt: r.CreatedAt.Unix(),
			ExpiresAt: r.ExpiresAt.Unix(),
			Current:   currentJTI != nil && r.JTI == currentJTI.(string),
		})
	}
	ok_(c, "ok", gin.H{"sessions": out, "total": len(out)})
}

// SessionsRevokeHandler revokes a session by its row id. Current session
// is allowed to revoke itself (equivalent to logout).
func SessionsRevokeHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	id := c.Param("id")
	now := time.Now()
	res := common.DB.Model(&models.Session{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).
		Update("revoked_at", &now)
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1002, "session not found or already revoked")
		return
	}
	ok_(c, "revoked", nil)
}

// SessionsRevokeAllHandler revokes every non-current session in one call.
// Equivalent to "Sign out of all other devices."
func SessionsRevokeAllHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	currentJTI, _ := c.Get("session_jti")
	now := time.Now()
	q := common.DB.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID)
	if currentJTI != nil {
		q = q.Where("jti <> ?", currentJTI.(string))
	}
	res := q.Update("revoked_at", &now)
	ok_(c, "revoked", gin.H{"revoked": res.RowsAffected})
}
