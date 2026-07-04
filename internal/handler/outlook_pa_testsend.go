package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// MeOutlookPATestSend — POST /api/v1/me/apps/lumid-outlook-pa/test-send
//
// Lets the user verify their POWER_AUTOMATE_SEND_URL flow without
// having to mint a PAT and run the skill from a shell. Reads the
// caller's stored URL, POSTs the body to it, surfaces the upstream
// status + (truncated) response. Never exposes the URL itself to the
// browser.
//
// Body (all optional with defaults):
//
//	{"to": "...", "subject": "...", "body": "..."}
//
// Defaults: to=caller's email, subject="Lumid test", body=link to docs.
type outlookPATestBody struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func MeOutlookPATestSend(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	// Fetch the stored secret value (decrypt server-side; never sent
	// to the browser even on this endpoint).
	var sec models.AppSecret
	err := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userID, "lumid-outlook-pa", "POWER_AUTOMATE_SEND_URL").First(&sec).Error
	if err == gorm.ErrRecordNotFound {
		fail(c, http.StatusBadRequest, 1404,
			"POWER_AUTOMATE_SEND_URL not set — save your flow URL on this page first")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "secret lookup: "+err.Error())
		return
	}
	flowURL, err := common.DecryptGrant(sec.ValueEncrypted)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "decrypt: "+err.Error())
		return
	}

	// Defaults: if no To given, send to the caller's own email. We
	// already have it on the user record; look it up.
	var body outlookPATestBody
	_ = c.ShouldBindJSON(&body)
	if body.To == "" {
		var u models.User
		if err := common.DB.Where("id = ?", userID).First(&u).Error; err == nil {
			body.To = u.Email
		}
	}
	if body.To == "" {
		fail(c, http.StatusBadRequest, 1400, "no 'to' address — provide one or set an email on your account")
		return
	}
	if body.Subject == "" {
		body.Subject = "Lumid → Outlook test"
	}
	if body.Body == "" {
		body.Body = "If you're seeing this in your Outlook inbox, the Power Automate bridge is working end-to-end.\n\nSent via lumid-outlook-pa."
	}

	payload, _ := json.Marshal(map[string]any{
		"to":      body.To,
		"subject": body.Subject,
		"body":    body.Body,
	})

	// Short timeout — Power Automate's HTTP-trigger flows reply with
	// 202 Accepted within a second or two once the action queue takes
	// the request. A slow response usually means a misconfigured flow.
	req, err := http.NewRequest("POST", flowURL, bytes.NewReader(payload))
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "build request: "+err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "POST to flow failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

	// Truncate response body for the response — Power Automate
	// occasionally returns large HTML error pages on schema mismatch.
	preview := string(respBody)
	if len(preview) > 800 {
		preview = preview[:800] + "…"
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"sent_to":               body.To,
			"subject":               body.Subject,
			"flow_status":           resp.StatusCode,
			"flow_ok":               resp.StatusCode < 400,
			"flow_response_preview": preview,
			"note":                  "Check your Outlook inbox + Sent folder. Latency: 1–30s.",
		},
	})
}
