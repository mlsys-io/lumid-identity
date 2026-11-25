package handler

// Batch "does this user still exist?" for service callers.
//
//   POST /api/v1/internal/users/exists   (X-Bridge-Secret)
//   {"subs": ["<user id>", ...]}
//
// The scheduler runs app loops for every tenant tree under ~/.tenants/<sub>/,
// and a tree outlives its account: delete the user and the installs keep
// firing cycles that can only fail (measured 2026-11-25 on the home shards:
// 150 of 186 quant-research tenants had no user row; 73 harvest_outbox loops
// suspended after failing on a missing credential). The scheduler needs to
// stop scheduling those tenants, and an archive tool needs to move their trees
// aside — both are only safe on an answer that cannot be confused with an
// outage.
//
// The two signals that existed before could not give that answer. Both
// /internal/mint-user-token and GET /admin/users/:id answered 404 "user not
// found" for ANY error from `First` — a dropped MySQL connection included —
// so a database blip read as "every tenant is gone". This route answers
// exists:false ONLY for ids the query positively did not return, and fails
// the whole request (5xx, no per-user verdicts) when the query errors.
//
// Read-only. Returns existence + status only — never email, role or tokens —
// so the response carries nothing a caller could act as.

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// maxUsersExistsBatch bounds one request. A scheduler shard holds ~70 tenants
// and the archive tool chunks; 500 keeps the IN list well inside MySQL limits.
const maxUsersExistsBatch = 500

type usersExistsBody struct {
	Subs []string `json:"subs"`
}

type userExistsVerdict struct {
	Exists bool   `json:"exists"`
	Status string `json:"status,omitempty"` // active | suspended | pending; only when exists
}

// lookupUserStatuses returns id -> status for every id in ids that has a users
// row. An id absent from the map was positively not found; a non-nil error
// means NOTHING about any id is known. Package var so tests can stub it.
var lookupUserStatuses = func(ids []string) (map[string]string, error) {
	var rows []models.User
	if err := common.DB.Model(&models.User{}).
		Select("id", "status").
		Where("id IN ?", ids).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, u := range rows {
		out[u.ID] = u.Status
	}
	return out, nil
}

// InternalUsersExists — POST /api/v1/internal/users/exists (X-Bridge-Secret).
func InternalUsersExists(c *gin.Context) {
	var b usersExistsBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	ids := make([]string, 0, len(b.Subs))
	seen := make(map[string]bool, len(b.Subs))
	for _, s := range b.Subs {
		s = strings.TrimSpace(s)
		if s == "" {
			fail(c, http.StatusBadRequest, 1400, "subs must not contain empty ids")
			return
		}
		if !seen[s] {
			seen[s] = true
			ids = append(ids, s)
		}
	}
	if len(ids) == 0 {
		fail(c, http.StatusBadRequest, 1400, "subs required")
		return
	}
	if len(ids) > maxUsersExistsBatch {
		fail(c, http.StatusBadRequest, 1400, "too many subs (max 500 per request)")
		return
	}
	found, err := lookupUserStatuses(ids)
	if err != nil {
		// Never a per-user verdict on a failed query: a caller that reads
		// "not found" here would orphan every tenant at once.
		fail(c, http.StatusServiceUnavailable, 1503, "user lookup failed: "+err.Error())
		return
	}
	users := make(map[string]userExistsVerdict, len(ids))
	missing := 0
	for _, id := range ids {
		if st, okk := found[id]; okk {
			users[id] = userExistsVerdict{Exists: true, Status: st}
		} else {
			users[id] = userExistsVerdict{Exists: false}
			missing++
		}
	}
	ok(c, "ok", gin.H{
		"users":   users,
		"checked": len(ids),
		"missing": missing,
	})
}
