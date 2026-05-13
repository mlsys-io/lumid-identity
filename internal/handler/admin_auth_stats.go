package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// GET /admin/auth-stats — feeds the super-admin dashboard's "failed
// logins / hour" sparkline plus a 24h summary. Reads exclusively from
// audit_log so cost scales with traffic, not user count.
//
// Response shape matches what the dashboard chart consumes directly —
// no client-side bucketing.

type authStatsResp struct {
	Window   string             `json:"window"`           // e.g. "24h"
	Generated time.Time         `json:"generated_at"`
	Login    statsBucket        `json:"login"`
	OAuth    statsBucket        `json:"oauth"`
	Hourly   []hourBucket       `json:"hourly"`           // last 24, oldest first
}

type statsBucket struct {
	Total  int64 `json:"total"`
	Failed int64 `json:"failed"`
}

type hourBucket struct {
	Hour    string `json:"hour"`     // "2026-05-08T13:00:00Z"
	Total   int64  `json:"total"`
	Failed  int64  `json:"failed"`
}

func AdminAuthStats(c *gin.Context) {
	now := time.Now().UTC().Truncate(time.Hour)
	cutoff := now.Add(-24 * time.Hour)

	var resp authStatsResp
	resp.Window = "24h"
	resp.Generated = now

	// Aggregate login + oauth events. Status>=400 → failed.
	common.DB.Model(&models.AuditLog{}).
		Where("event = ? AND created_at >= ?", "login", cutoff).
		Count(&resp.Login.Total)
	common.DB.Model(&models.AuditLog{}).
		Where("event = ? AND status >= ? AND created_at >= ?", "login", 400, cutoff).
		Count(&resp.Login.Failed)
	common.DB.Model(&models.AuditLog{}).
		Where("event = ? AND created_at >= ?", "oauth", cutoff).
		Count(&resp.OAuth.Total)
	common.DB.Model(&models.AuditLog{}).
		Where("event = ? AND status >= ? AND created_at >= ?", "oauth", 400, cutoff).
		Count(&resp.OAuth.Failed)

	// Hourly buckets — single query that groups by hour.
	type bucket struct {
		Hour   time.Time
		Total  int64
		Failed int64
	}
	var rows []bucket
	common.DB.Raw(`
		SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00') AS hour,
		       COUNT(*) AS total,
		       SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS failed
		FROM audit_log
		WHERE event IN ('login','oauth') AND created_at >= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, cutoff).Scan(&rows)

	// Fill 24 buckets even if some are empty.
	byHour := make(map[string]bucket, len(rows))
	for _, r := range rows {
		byHour[r.Hour.UTC().Format(time.RFC3339)] = r
	}
	for i := 23; i >= 0; i-- {
		h := now.Add(-time.Duration(i) * time.Hour)
		key := h.Format(time.RFC3339)
		b := byHour[key]
		resp.Hourly = append(resp.Hourly, hourBucket{
			Hour:   key,
			Total:  b.Total,
			Failed: b.Failed,
		})
	}

	ok(c, "ok", resp)
}

// silence unused warning for http (kept for symmetry with other handlers)
var _ = http.StatusOK
