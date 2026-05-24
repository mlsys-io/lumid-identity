package handler

// Phase D4 — per-tenant external-API audit log.
//
// Surfaces usage_events rows (kind=external_api) the user can review:
// every Gmail send, calendar create, etc., the AI made on their
// behalf. Read-only, paginated, scoped to the calling user.
//
// The same rows that quota-counter against the Tier-1 cap (D in 0.6)
// are now also human-readable. No new write path needed.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type meAuditRow struct {
	Ts       string `json:"ts"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model,omitempty"`
	Meta     string `json:"meta,omitempty"`
}

// MeAudit serves GET /api/v1/me/audit?kind=&since_hours=&limit=
//
// Defaults: kind=external_api (the one users care about — Gmail
// sends, calendar creates, Slack posts). since_hours=168 (7 days).
// limit=200 (cap so the page renders fast even on chatty days).
func MeAudit(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	kind := c.DefaultQuery("kind", "external_api")
	sinceHours := 168
	if v := c.Query("since_hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*30 {
			sinceHours = n
		}
	}
	limit := 200
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	since := time.Now().UTC().Add(-time.Duration(sinceHours) * time.Hour)

	var events []models.UsageEvent
	q := common.DB.Where("user_sub = ? AND ts >= ?", userID, since).
		Order("ts DESC").
		Limit(limit)
	if kind != "all" {
		q = q.Where("kind = ?", kind)
	}
	if err := q.Find(&events).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "audit fetch: "+err.Error())
		return
	}

	out := make([]meAuditRow, 0, len(events))
	for _, e := range events {
		out = append(out, meAuditRow{
			Ts:       e.Ts.Format(time.RFC3339),
			Kind:     e.Kind,
			Endpoint: e.Endpoint,
			Model:    e.Model,
			Meta:     e.Meta,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"events":      out,
			"count":       len(out),
			"since_hours": sinceHours,
			"kind":        kind,
		},
	})
}
