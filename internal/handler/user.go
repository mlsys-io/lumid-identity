package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// GET /api/v1/user — return the current user based on the session
// cookie. This is what every frontend calls on mount to decide
// "logged in or not". 401 means no/expired session.
func CurrentUserHandler(c *gin.Context) {
	uid, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", uid).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	ok(c, "ok", gin.H{
		"id":                 u.ID,
		"email":              u.Email,
		"username":           u.Name,
		"role":               u.Role,
		"status":             u.Status,
		"avatar":             u.AvatarURL,
		"email_verified":     u.EmailVerified,
		"invitation_code":    u.InvitationCodeUsed,
	})
}
