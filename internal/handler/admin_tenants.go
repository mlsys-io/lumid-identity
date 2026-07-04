package handler

// /api/v1/admin/tenants — per-tenant operational snapshot for the
// super-admin dashboard. Joins:
//
//   - users table (id, email, role, created_at)
//   - on-disk tenant tree (/home/webmaster/.tenants/<sub>/.xp/apps/*)
//   - today's usage_events rolled up per (user_sub, kind)
//
// Read-only, admin-gated. Renders the "who's running what" tile so
// the operator can see at a glance which tenants are active, what
// they have installed, and how close they are to any cap.

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type tenantRow struct {
	Sub         string   `json:"sub"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	CreatedAt   string   `json:"created_at"`
	Apps        int      `json:"apps"`
	AppNames    []string `json:"app_names,omitempty"`
	StorageMB   float64  `json:"storage_mb"`
	CyclesToday int      `json:"cycles_today"`
	LLMTokens   int      `json:"llm_tokens_today"`
	GmailToday  int      `json:"gmail_today"`
	LastCycleTS string   `json:"last_cycle_ts,omitempty"`
}

// AdminTenants serves GET /api/v1/admin/tenants — RequireAdmin gates
// the route in router.go.
func AdminTenants(c *gin.Context) {
	var users []models.User
	if err := common.DB.Order("created_at DESC").Find(&users).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "users fetch: "+err.Error())
		return
	}

	// One grouped query for today's per-user totals — cheaper than
	// FetchTodayTotals(sub) N times.
	type usageAgg struct {
		UserSub  string
		Kind     string
		Endpoint string
		Tokens   int
		Cnt      int
		LastTs   time.Time
	}
	var aggs []usageAgg
	common.DB.Raw(`
		SELECT user_sub,
		       kind,
		       COALESCE(endpoint, '') AS endpoint,
		       COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens,
		       COUNT(*) AS cnt,
		       MAX(ts) AS last_ts
		FROM usage_events
		WHERE ts >= ?
		GROUP BY user_sub, kind, endpoint`, common.TodayBound()).Scan(&aggs)

	// Roll up by user_sub.
	perUser := map[string]*tenantRow{}
	for _, a := range aggs {
		row, ok := perUser[a.UserSub]
		if !ok {
			row = &tenantRow{Sub: a.UserSub}
			perUser[a.UserSub] = row
		}
		switch a.Kind {
		case "cycle_start":
			row.CyclesToday += a.Cnt
		case "cycle_llm":
			row.LLMTokens += a.Tokens
		case "external_api":
			if a.Endpoint == "gmail.send" {
				row.GmailToday += a.Cnt
			}
		}
		if a.LastTs.After(time.Time{}) {
			ts := a.LastTs.Format(time.RFC3339)
			if ts > row.LastCycleTS {
				row.LastCycleTS = ts
			}
		}
	}

	// Walk each tenant tree once for apps + storage. Cached via
	// measureTenantStorage so repeated dashboard polls don't du-bomb.
	out := make([]tenantRow, 0, len(users))
	for _, u := range users {
		r := tenantRow{
			Sub:       u.ID,
			Email:     u.Email,
			Role:      u.Role,
			CreatedAt: u.CreatedAt.Format(time.RFC3339),
		}
		if existing, ok := perUser[u.ID]; ok {
			r.CyclesToday = existing.CyclesToday
			r.LLMTokens = existing.LLMTokens
			r.GmailToday = existing.GmailToday
			r.LastCycleTS = existing.LastCycleTS
		}
		// Apps on disk
		appsDir := filepath.Join(operatorHome(), ".tenants", u.ID, ".xp", "apps")
		if entries, err := os.ReadDir(appsDir); err == nil {
			for _, e := range entries {
				if e.IsDir() && len(e.Name()) > 0 && e.Name()[0] != '.' {
					r.Apps++
					r.AppNames = append(r.AppNames, e.Name())
				}
			}
		}
		// Storage — uses the cached snapshot helper
		if r.Apps > 0 {
			snap := measureTenantStorage(u.ID)
			r.StorageMB = float64(snap.usedBytes) / (1024 * 1024)
		}
		out = append(out, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"tenants": out,
			"count":   len(out),
			"as_of":   time.Now().UTC().Format(time.RFC3339),
		},
	})
}
